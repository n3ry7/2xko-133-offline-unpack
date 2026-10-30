# 1. Unpacking the packer

## What the packed binary looks like

| property | packed 1.3.3 | 1.2.5 (reference, not packed) |
|---|---|---|
| `.text` characteristics | `0x20` (not code, not executable) | `0x60000020` |
| imports | `stub.dll` only | normal import table |
| extra sections | `.toir`, `.stub` | — |

Under Proton the packed exe exits silently right after an RPC to the service manager
(`ntdll`/`rpcrt4` in the trace). Under Windows it runs normally, which is why dumping
had to happen on Windows.

## Strategy: fault each page and let the packer decrypt it

A packed image of this kind decrypts on demand: the first time a page is executed it
faults (the page is `NOACCESS`/`PAGE_GUARD`), the packer's handler decrypts the page,
changes the protection, and resumes.

So to obtain the plaintext of every page:

1. Start the game with `CREATE_SUSPENDED` / launch normally and attach.
2. Create a thread, set its RIP to a page boundary, set the trap flag, resume.
3. The fetch faults → the packer decrypts the page and makes it readable.
4. After one instruction the single-step trap fires; stop or park the thread, read the
   page.
5. Repeat for the next page.

This is `tfwalk8.py` (and its ancestors `tfwalk.py` … `tfwalk7.py`, kept nowhere in
this repo except the final one).

## Things that made this hard

- **Private pages stop executing.** The first attempts put the stub and handler in a
  private `VirtualAllocEx` page; the packer stopped executing them. The stubs must live
  in an **image page**. `find_host()` locates a writable host inside a loaded module's
  BSS (found in `libcef.dll`). `VirtualProtectEx` fails with error 87 on every
  `Lion-Win64-Shipping.exe` page, which is why the host is elsewhere.
- **VEH ordering.** Walking the vectored-handler chain (`vehwalk.py`) is necessary to
  get *behind* the packer's handler. Enabling it requires `PEB->CrossProcessFlags`
  bit 2, and the handler pointer inside the entry returned by
  `AddVectoredExceptionHandler` is **encoded** (`EncodePointer`, `ntdll+0xe7290`).
- **`time.sleep` granularity on Windows** is 1–15 ms, which is far too coarse when
  polling for the protection flip. The wait loops busy-wait on `QueryPerformanceCounter`.
- **The packer tires.** After roughly 1,000–2,500 faults in one process it stops
  decrypting; every further page burns the timeout. `tfwalk8.py` counts pages since the
  last successful dump and the harness relaunches the game after 150 misses
  (`auto.ps1`). Dump state is resumable: a bitmap (`dumped.bin`) plus `next.txt`, both
  written atomically, and `recover.py` rebuilds the bitmap from `text.bin` if needed.

## The corruption bug that cost a full extra pass

The first pass produced a complete `.text` that booted the game to the FRE level and
then died on what looked like AVX-512 code at RVA `0x2ce0`. Reading the *live* packed
process settled it:

```
live  48 81 ec 88 00 00 00  c5 78 29 6c 24 70   sub rsp,0x88; vmovaps [rsp+0x70],xmm6
dump  d5 28 58 c0 62 a1 dd 20  ...              EVEX garbage
```

The packer changes the protection to `RX` **before** it finishes writing the plaintext.
The dumper read as soon as the protection flipped, so a few pages were captured
half-written. Pages the *game* itself decrypted were perfect — 2,683 checked, 0
differed — which localised the problem to pages decrypted by the walker.

**Fix:** `stable_read()` only accepts a page when two consecutive reads, 5 ms apart,
are identical (up to 10 tries):

```python
def stable_read(h, addr, n):
    prev = None
    for _ in range(10):
        cur = fp.read_bytes(h, addr, n)
        if cur is not None and len(cur) == n:
            if prev is not None and cur == prev:
                return cur
            prev = cur
        time.sleep(0.005)
    return prev
```

The second pass re-dumped from page 0 with that rule; the known-good bytes at `0x2ce0`
(`4881ec88…`) were reproduced exactly, which is how the fix was verified rather than
assumed.

## Entry point

OEP is **RVA `0x7e698b0`**:

```
sub  rsp, 0x28
call <__security_init_cookie>
jmp  __scrt_common_main_seh
```

The 1.2.5 build (not packed) has the same shape at RVA `0x7e3b230`, which is what
confirmed the candidate. `findoep2.py` captures it by breaking on the first execution
of the decrypted section and reading the context.

The SIMD-dispatch global at RVA `0xAB7CBF0` reads 4 ("AVX2") on both test machines,
which is why the kernel at `0x2ce0` must be genuine AVX2 — an AVX-512 build would have
hidden the corruption.

## Import table

The packer's IAT starts at **RVA `0x8011000`** (inside `.rdata`, which is why the
rebuilt exe must mark `.rdata` writable). Blocks are separated by the sentinel
`0xC01F9CEFB0F443AF` instead of a null terminator, and slots resolve to forwarders,
so the table cannot be declared to the loader directly.

`buildimports.py` reads the live image, walks the sentinel-delimited blocks, resolves
each slot back to `module!name`, and writes `dumpimg/imports.json`: **1,214 imports
across 36 modules**. Only 3 slots in the whole range are not imports (they point back
into the game itself).

## Rebuild

`rebuild2.py` takes the packed file, writes the decrypted `.text` over the encrypted
bytes, marks `.text` executable (`0x60000020`), makes `.rdata` writable
(`0xC0000040`), appends a `.boot` section (`0xE0000020`, RWX — the bootstrap stores
resolved pointers and module handles in it), repoints `AddressOfEntryPoint` to
`.boot`, and updates `SizeOfImage`.

`SizeOfImage` ends up `0xbf05000` for a 195,327,488-byte file.

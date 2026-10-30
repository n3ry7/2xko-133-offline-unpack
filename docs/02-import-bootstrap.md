# 2. The import bootstrap (why the loader was bypassed)

## Symptom

The first rebuilt exe ran fine under Wine but died natively on Windows:

```
Faulting application name: Lion-Win64-Shipping.exe
Exception code: 0xc0000005
Fault offset: 0x0000000000000000
```

RIP = 0, no `Lion.log`, only 4 modules loaded (`exe`, `ntdll`, `kernel32`,
`kernelbase`). That is a call through a null IAT slot — but the bootstrap had just
filled the IAT from the loader's import table.

## Proof that Windows ignored the import directory

The descriptor itself was valid: `pefile` parsed it (`KERNEL32.dll →
LoadLibraryA, GetProcAddress`), the section table was consistent, `SizeOfHeaders`
covered the new header, and nothing overlapped.

Two experiments settled it:

1. **Bogus DLL name.** Patch the descriptor's `Name` to `NOPE32.dll` (a module that does
   not exist). If the loader honours the directory, `CreateProcess` must fail with
   "module not found". It started anyway — and still died at RIP 0 with a zero IAT.
2. **Read the IAT at the crash.** `.boot+0x100` was still `00 00 …`, and the return
   address on the stack was `.boot+0x49`, i.e. the first `call [rip+iat0]`.

So the loader skipped import resolution for this image without reporting an error.
Rather than keep guessing at the loader's reasons, the bootstrap was made independent
of it.

## The resolver

The rebuilt exe now has **no import directory at all** (`DataDirectory[1] = {0,0}`).
`.boot` finds what it needs itself:

```
1. rax = gs:[0x60]              ; PEB
   rax = [rax+0x18]             ; PEB->Ldr
   rax = [rax+0x10]             ; InLoadOrderModuleList.Flink
2. walk up to 16 entries, for each:
     base = [entry+0x30]  (LdrDataTableEntry.DllBase)
     check 'MZ', check e_lfanew -> 'PE\0\0'
     exportRVA = [base+e_lfanew+0x88]   ; OptionalHeader.DataDirectory[0]
     nameRVA   = [base+exportRVA+0x0c]
     compare first 8 bytes of the export module name to "KERNEL32"
3. parse that export directory:
     NumberOfNames          [dir+0x18]
     AddressOfNames         [dir+0x20] + base
     AddressOfNameOrdinals  [dir+0x24] + base
     AddressOfFunctions     [dir+0x1c] + base
4. scan names for the 8-byte prefixes "LoadLibr" and "GetProcA", confirm the tails
   "aryA" (dword at +8) and "dre"/"ss" (dword at +8, word at +0xc), take
   AddressOfFunctions[ordinal] + base
5. for each of the 1,214 imports:
     handle = cache[moduleIndex] ?: LoadLibraryA(modName)
     addr   = GetProcAddress(handle, name)
     *slot  = addr
6. jmp base + 0x7e698b0
```

Forwarders were checked and are not a problem here: `LoadLibraryA` and `GetProcAddress`
are real code (not forwarder strings) in Windows `KERNEL32.dll` **and** in Wine's
`kernel32.dll` and `kernelbase.dll`. That check matters because a forwarder would have
made step 4 return a pointer to a string.

## Section layout

```
0x000  code                        (536 bytes)
0x740  resolved LoadLibraryA
0x748  resolved GetProcAddress
0x750  marker byte: base = va(marker) - 0xbef8750
0x760  module handle cache (64 x u64)
0x960  module name RVA table (64 x u32)
0xa80  entries: {slotRVA, moduleIndex, nameRVA, pad} x 1,214
...    string pool: module names, then import names
```

`mkboot.py` is a tiny hand-rolled x64 emitter with label fixups, plus a `capstone`
disassembly dump so the generated code can be reviewed before it is ever executed.

## Bugs found while writing it (all caught by reading the disassembly)

- `mov r10d, [r13+rax*4]` needs an explicit zero displacement: `mod=00` with base
  `r13` (like `rbp`) means "no base + disp32", so the bytes silently consumed the next
  instruction. Correct form: `45 8b 54 85 00`.
- The resolved slots were stored with **section offsets** instead of RVAs
  (`[r15+0x740]` instead of `[r15+0xbef8740]`), which wrote into the read-only header
  page. This produced a very clean `0xc0000005` at `0xbef810c` with the faulting
  address `0x140000740` — i.e. `base + 0x740`.
- `[r15+disp32]` does **not** need a SIB byte (`rm = 111`); adding one shifts the
  displacement by a byte.

## Verifying the bootstrap

- Windows: a debug loop (`tools/dbgrun.py`) reports first-chance exceptions with
  `RIP`/`RSP`, the stack's return addresses, the module map, and the `.boot` IAT.
  A good run loads 89 modules, including `OpenColorIO_2_3.dll` (the module whose
  `LoadLibraryA` had previously appeared to fail — that was only ever a working-directory
  artefact of the test harness).
- Wine: the same exe reaches the FRE level, so the resolver is equally valid there.

## Note on the 86 "failing" imports

An earlier check reported 86 imports failing against `OpenColorIO_2_3.dll`. That was
the test script running from the wrong directory: with the game's `Binaries\Win64`
added to the search path, all 36 modules load and all 1,214 names resolve.

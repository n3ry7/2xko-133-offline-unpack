"""vehwalk.py - decrypt every .text page, allowing exactly one instruction to run.

What dumpwalk.py showed: an execute fault decrypts the page (NOACCESS -> RX in
~6 ms), but the thread then keeps running real game code with a foreign stack
and the process dies within a few pages. Some of those pages are the packer's
own error paths, which call TerminateProcess.

So the page must be decrypted and then execution stopped immediately. That needs
a trap after exactly one instruction, and a handler of our own to receive it:

  1. a stub in a private page calls AddVectoredExceptionHandler(1, handler).
     A VEH registered last is called first, so ours sees exceptions before the
     packer's handler.
  2. the handler passes everything through (return 0) EXCEPT
     STATUS_SINGLE_STEP with RIP inside .text. For that it clears TF, sets
     RIP to a safe stub and returns -1 (EXCEPTION_CONTINUE_EXECUTION).
  3. per page: create the thread suspended, set RIP = page and TF = 1 in its
     context, verify the write took, resume.
        fetch at page -> AV -> our handler passes it -> packer decrypts and
        resumes -> one instruction runs -> #DB -> our handler redirects to the
        safe stub -> thread returns 0x5A5A.
  4. dump the page, then the next one. Resumable via textdump/*.bin.

If the context write is ignored the readback check aborts before resuming, so a
page is never executed without the trap in place.

    python vehwalk.py <pid|exe> [--max-pages N] [--setup-only]
"""
import ctypes
import ctypes.wintypes as w
import os
import struct
import sys
import time

sys.path.insert(0, r'C:\2XKO-unpack')
import faultprobe as fp

PAGE = 0x1000
OUT = r'C:\2XKO-unpack\textdump'
SAFE_EXIT = 0x5A5A
CREATE_SUSPENDED = 0x0004
CONTEXT_FULL = 0x00100003
STATUS_SINGLE_STEP = 0x80000004
TF = 0x100
EFLAGS = 0x44
RIP = 0xF8

k32 = fp.k32
k32.TerminateThread.argtypes = [w.HANDLE, w.DWORD]
k32.TerminateThread.restype = w.BOOL
k32.ResumeThread.argtypes = [w.HANDLE]
k32.SuspendThread.argtypes = [w.HANDLE]
k32.GetModuleHandleW.restype = w.HMODULE
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [w.HMODULE, w.LPCSTR]


class CONTEXT(ctypes.Structure):
    _fields_ = [('buf', ctypes.c_ubyte * 0x4d0)]


k32.GetThreadContext.argtypes = [w.HANDLE, ctypes.POINTER(CONTEXT)]
k32.SetThreadContext.argtypes = [w.HANDLE, ctypes.POINTER(CONTEXT)]


def ctx_new():
    c = CONTEXT()
    ctypes.memset(ctypes.byref(c), 0, ctypes.sizeof(c))
    ctypes.c_uint32.from_buffer(c, 0x30).value = CONTEXT_FULL
    return c


def get_ctx(h_thread):
    c = ctx_new()
    if not k32.GetThreadContext(h_thread, ctypes.byref(c)):
        return None, ctypes.get_last_error()
    return c, 0


def put_ctx(h_thread, c):
    ctypes.c_uint32.from_buffer(c, 0x30).value = CONTEXT_FULL
    return bool(k32.SetThreadContext(h_thread, ctypes.byref(c)))


def ctx_fields(c):
    raw = bytes(c.buf)
    return (struct.unpack_from('<Q', raw, RIP)[0],
            struct.unpack_from('<I', raw, EFLAGS)[0],
            struct.unpack_from('<Q', raw, 0x98)[0])


def wr(h, addr, data):
    got = ctypes.c_size_t(0)
    ok = k32.WriteProcessMemory(h, ctypes.c_void_p(addr), data, len(data),
                                ctypes.byref(got))
    return bool(ok) and got.value == len(data)


def rd(h, addr, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)):
        return None
    return buf.raw[:got.value]


# ---------------------------------------------------------------- handler ----
def build_handler(text_lo, text_hi, safe_addr):
    """rcx = PEXCEPTION_POINTERS; returns EXCEPTION_CONTINUE_SEARCH (0) or
    EXCEPTION_CONTINUE_EXECUTION (-1)."""
    b = bytearray()
    fix = []

    def emit(x):
        b.extend(x)

    def rel8(op, target_label):
        emit(op)
        fix.append((len(b), target_label))
        emit(b'\x00')

    emit(b'\x48\x8b\x11')                          # mov rdx,[rcx]
    emit(b'\x8b\x02')                              # mov eax,[rdx]
    emit(b'\x3d' + struct.pack('<I', STATUS_SINGLE_STEP))
    rel8(b'\x75', 'pass')                          # jne pass
    emit(b'\x48\x8b\x51\x08')                      # mov rdx,[rcx+8]
    emit(b'\x48\x8b\x82' + struct.pack('<I', RIP))  # mov rax,[rdx+Rip]
    emit(b'\x49\xb8' + struct.pack('<Q', text_lo))  # mov r8,text_lo
    emit(b'\x4c\x39\xc0')                          # cmp rax,r8
    rel8(b'\x72', 'pass')                          # jb pass
    emit(b'\x49\xb8' + struct.pack('<Q', text_hi))  # mov r8,text_hi
    emit(b'\x4c\x39\xc0')                          # cmp rax,r8
    rel8(b'\x73', 'pass')                          # jae pass
    emit(b'\xc7\x82' + struct.pack('<I', EFLAGS) + struct.pack('<I', 0x202))
    emit(b'\x48\xb8' + struct.pack('<Q', safe_addr))    # mov rax,safe
    emit(b'\x48\x89\x82' + struct.pack('<I', RIP))      # mov [rdx+Rip],rax
    emit(b'\xb8\xff\xff\xff\xff')                  # mov eax,-1
    emit(b'\xc3')                                  # ret
    labels = {'pass': len(b)}
    emit(b'\x31\xc0')                              # xor eax,eax
    emit(b'\xc3')                                  # ret
    for at, lab in fix:
        tgt = labels[lab]
        b[at] = (tgt - (at + 1)) & 0xff
    return bytes(b)


def build_safe():
    return b'\xb8' + struct.pack('<I', SAFE_EXIT) + b'\xc3'     # mov eax,0x5A5A; ret


def build_register(aveh, handler):
    return (b'\x48\xb8' + struct.pack('<Q', aveh)     # mov rax,AddVectoredExceptionHandler
            + b'\x48\xc7\xc1\x01\x00\x00\x00'         # mov rcx,1
            + b'\x48\xba' + struct.pack('<Q', handler)  # mov rdx,handler
            + b'\x48\x83\xec\x28'                     # sub rsp,0x28  (shadow space)
            + b'\xff\xd0'                             # call rax
            + b'\x48\x83\xc4\x28'                     # add rsp,0x28
            + b'\xb8\x7e\x7e\x7e\x7e'                 # mov eax,0x7E7E7E7E
            + b'\xc3')


def run_once(h, entry, tries=300, wait_ms=150):
    """Create threads at `entry` until one actually runs; return its exit code."""
    for i in range(1, tries + 1):
        if not fp.alive(h):
            return None, i, 'process died'
        tid = w.DWORD(0)
        th = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(entry), None, 0,
                                    ctypes.byref(tid))
        if not th:
            return None, i, f'create err {ctypes.get_last_error()}'
        k32.WaitForSingleObject(th, wait_ms)
        ec = w.DWORD(0)
        k32.GetExitCodeThread(th, ctypes.byref(ec))
        k32.CloseHandle(th)
        if ec.value not in (0, 259):
            return ec.value, i, ''
    return 0, tries, 'never ran'


# ------------------------------------------------------------------ state ----
def load_state(npages, vsz):
    os.makedirs(OUT, exist_ok=True)
    dp = os.path.join(OUT, 'dumped.bin')
    tp = os.path.join(OUT, 'text.bin')
    if os.path.exists(dp) and os.path.exists(tp):
        dumped = bytearray(open(dp, 'rb').read())
        if len(dumped) != npages:
            raise SystemExit(f'{dp} has {len(dumped)} entries, expected {npages}')
    else:
        dumped = bytearray(npages)
        disk = open(fp.DISK, 'rb').read()
        t = fp.sections_of(fp.DISK)['.text']
        body = disk[t['raw']:t['raw'] + vsz]
        body += b'\x00' * (vsz - len(body))
        open(tp, 'wb').write(body)
        open(dp, 'wb').write(bytes(dumped))
    return dumped


def save_dumped(dumped):
    open(os.path.join(OUT, 'dumped.bin'), 'wb').write(bytes(dumped))


def save_page(off, data):
    with open(os.path.join(OUT, 'text.bin'), 'r+b') as f:
        f.seek(off)
        f.write(data)


def main():
    pid, h = fp.open_target(sys.argv[1])
    base, path = fp.main_module(h)
    t = fp.sections_of(fp.DISK)['.text']
    vsz = t['vsz']
    addr0 = base + t['va']
    npages = (vsz + PAGE - 1) // PAGE
    setup_only = '--setup-only' in sys.argv
    max_pages = None
    for i, a in enumerate(sys.argv):
        if a == '--max-pages':
            max_pages = int(sys.argv[i + 1])

    print(f'pid {pid}  base {base:#x}  .text {addr0:#x} + {vsz:#x}')

    k32h = k32.GetModuleHandleW('kernel32')
    aveh = k32.GetProcAddress(k32h, b'AddVectoredExceptionHandler')
    if not aveh:
        raise SystemExit('AddVectoredExceptionHandler not found')

    code = k32.VirtualAllocEx(h, None, 0x1000, 0x3000, 0x40)
    safe_addr = code + 0x100
    handler = build_handler(addr0, addr0 + vsz, safe_addr)
    wr(h, code, handler)
    wr(h, code + 0x100, build_safe())
    reg = build_register(aveh, code)
    wr(h, code + 0x300, reg)
    print(f'code {code:#x}  handler {len(handler)} bytes  safe {safe_addr:#x}')
    print(f'handler: {handler.hex()}')

    ec, n, err = run_once(h, code + 0x300)
    print(f'register VEH: exit {"None" if ec is None else hex(ec)} after {n} attempt(s) {err}')
    if ec != 0x7E7E7E7E:
        print('could not run the registration stub - aborting')
        return 2
    print('VEH registered\n')
    if setup_only:
        return 0

    dumped = load_state(npages, vsz)
    todo = [i for i in range(npages) if not dumped[i]]
    print(f'pages to dump: {len(todo)} of {npages}')
    if not todo:
        return 0

    t0 = time.time()
    done = 0
    unsafe = 0
    for i in todo:
        if max_pages is not None and done >= max_pages:
            break
        if not fp.alive(h):
            print(f'\nprocess died after {done} pages')
            save_dumped(dumped)
            return 2
        addr = addr0 + i * PAGE
        off = i * PAGE
        nbytes = min(PAGE, vsz - off)

        if fp.readable(h, addr, 4):
            data = rd(h, addr, nbytes)
            if data and len(data) == nbytes:
                save_page(off, data)
                dumped[i] = 1
            done += 1
            continue

        prot = fp.prot_at(h, addr)
        if prot is None or (prot[0] & 0xff) != fp.PAGE_NOACCESS:
            done += 1
            continue

        tid = w.DWORD(0)
        th = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(addr), None,
                                    CREATE_SUSPENDED, ctypes.byref(tid))
        if not th:
            print(f'page {i}: create failed err {ctypes.get_last_error()}')
            break
        c, e = get_ctx(th)
        if c is None:
            print(f'page {i}: GetThreadContext failed err {e}')
            k32.TerminateThread(th, 0)
            k32.CloseHandle(th)
            break
        raw = bytearray(bytes(c.buf))
        struct.pack_into('<Q', raw, RIP, addr)
        struct.pack_into('<I', raw, EFLAGS, struct.unpack_from('<I', raw, EFLAGS)[0] | TF)
        ctypes.memmove(ctypes.byref(c), bytes(raw), len(raw))
        if not put_ctx(th, c):
            print(f'page {i}: SetThreadContext failed err {ctypes.get_last_error()}')
            k32.TerminateThread(th, 0)
            k32.CloseHandle(th)
            break
        c2, _ = get_ctx(th)
        rip2, ef2, _ = ctx_fields(c2) if c2 else (0, 0, 0)
        if rip2 != addr or not (ef2 & TF):
            print(f'page {i}: context write IGNORED (rip {rip2:#x} eflags {ef2:#x}) - abort')
            k32.TerminateThread(th, 0)
            k32.CloseHandle(th)
            return 3

        k32.ResumeThread(th)
        ok = False
        t1 = time.time()
        while time.time() - t1 < 0.3:
            if fp.readable(h, addr, 4):
                ok = True
                break
            if not fp.alive(h):
                break
            time.sleep(0.001)
        ec = w.DWORD(0)
        k32.GetExitCodeThread(th, ctypes.byref(ec))
        if ec.value == 259:
            k32.TerminateThread(th, 0)
        k32.CloseHandle(th)

        if ok:
            data = rd(h, addr, nbytes)
            if data and len(data) == nbytes:
                save_page(off, data)
                dumped[i] = 1
        else:
            unsafe += 1
        done += 1
        if done % 100 == 0:
            save_dumped(dumped)
            el = time.time() - t0
            print(f'  {npages - sum(dumped)} left  {done} this run  '
                  f'{done / el:5.1f} pages/s  '
                  f'eta {(len(todo) - done) / (done / el) / 60:5.1f} min  '
                  f'no-decrypt {unsafe}', flush=True)
        if unsafe > 25:
            print('\ntoo many pages failed to decrypt - stopping')
            save_dumped(dumped)
            return 4

    save_dumped(dumped)
    print(f'\nrun done: {done} pages, {time.time() - t0:.0f}s  '
          f'dumped {sum(dumped)}/{npages}  no-decrypt {unsafe}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

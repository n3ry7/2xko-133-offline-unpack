"""readlive.py - compare the live decrypted page with my dump, and read the level.

If page 0x2000 is still NOACCESS we force it to decrypt by faulting at 0x2ce0 with
the usual trap, then read the bytes. Also prints the SIMD level global at
rva 0xAB7CBF0 (the value the dispatcher at 0x8bb0 reads).

    python readlive.py <pid|exe>
"""
import ctypes
import ctypes.wintypes as w
import struct
import sys
import time

sys.path.insert(0, r'C:\2XKO-unpack')
import faultprobe as fp
from vehwalk import RIP, EFLAGS, TF, PAGE, CREATE_SUSPENDED, get_ctx, put_ctx
from vehtest import build_register2
from tfwalk6 import build_handler, find_host, CPU

k32 = fp.k32
HANDLE_SLOT = 0x1A0


def q(h, a):
    return struct.unpack_from('<Q', fp.read_bytes(h, a, 8) or bytes(8), 0)[0]


def rd(h, a, n):
    return fp.read_bytes(h, a, n)


def main():
    pid, h = fp.open_target(sys.argv[1])
    base, _ = fp.main_module(h)
    t = fp.sections_of(fp.DISK)['.text']
    TARGET = base + int(sys.argv[2], 0)
    print(f'target rva {int(sys.argv[2],0):#x}')
    dump = open(r'C:\2XKO-unpack\textdump\text.bin', 'rb').read()
    print(f'pid {pid}  base {base:#x}')

    lvl = rd(h, base + 0xAB7CBF0, 4)
    print('level global 0xAB7CBF0 =', struct.unpack('<i', lvl)[0] if lvl else None)

    page = TARGET & ~0xFFF
    time.sleep(0.02)
    prot = fp.prot_at(h, page)
    print('page 0x2000 protection:', fp.prot_name(prot[0]) if prot else None)

    def show(tag):
        b = rd(h, TARGET, 32)
        if b is None:
            print(f'  {tag}: unreadable')
            return
        rva = TARGET - base
        mine = dump[rva - t['va']:rva - t['va'] + len(b)]
        print(f'  {tag} live {b.hex()}')
        print(f'  {" " * len(tag)} dump {mine.hex()}   identical={b == mine}')

    if fp.readable(h, TARGET, 4):
        print('page already readable')
        show('now')
        return 0

    # force the page to decrypt the same way the dumper does
    k32.GetModuleHandleW.restype = ctypes.c_void_p
    k32.GetProcAddress.restype = ctypes.c_void_p
    k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    aveh = k32.GetProcAddress(k32.GetModuleHandleW('kernel32'),
                              b'AddVectoredExceptionHandler')
    code = find_host(h)
    if not code:
        print('no host page'); return 2
    old = w.DWORD(0)
    k32.VirtualProtectEx(h, ctypes.c_void_p(code), PAGE, 0x40, ctypes.byref(old))
    ps = ctypes.c_size_t(0)
    hh = build_handler(code)
    k32.WriteProcessMemory(h, ctypes.c_void_p(code), hh, len(hh), ctypes.byref(ps))
    k32.WriteProcessMemory(h, ctypes.c_void_p(code + CPU['SAFE']), b'\xeb\xfe', 2, ctypes.byref(ps))
    stub = build_register2(aveh, code, code + HANDLE_SLOT)
    k32.WriteProcessMemory(h, ctypes.c_void_p(code + 0x300), stub, len(stub), ctypes.byref(ps))

    reg = None
    for attempt in range(1, 1201):
        if not fp.alive(h):
            print('died while registering'); return 2
        tid = w.DWORD(0)
        th = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(code + 0x300), None, 0,
                                    ctypes.byref(tid))
        if not th:
            continue
        k32.WaitForSingleObject(th, 100)
        ecv = w.DWORD(0)
        k32.GetExitCodeThread(th, ctypes.byref(ecv))
        k32.CloseHandle(th)
        if ecv.value == 0x7E7E7E7E:
            reg = attempt
            break
    if reg is None:
        print('registration never ran'); return 2
    entry = q(h, code + HANDLE_SLOT)
    ntdll = None
    arr = (w.HMODULE * 1024)(); need = w.DWORD(0)
    fp.psapi.EnumProcessModulesEx(h, arr, ctypes.sizeof(arr), ctypes.byref(need), 0x03)
    for i in range(need.value // ctypes.sizeof(w.HMODULE)):
        buf = ctypes.create_unicode_buffer(1024)
        fp.psapi.GetModuleFileNameExW(h, arr[i], buf, 1024)
        if buf.value.lower().endswith('ntdll.dll'):
            ntdll = ctypes.cast(arr[i], ctypes.c_void_p).value
    head = ntdll + 0x1EB580
    k32.VirtualProtectEx(h, ctypes.c_void_p(head), PAGE, 0x04, ctypes.byref(old))
    if q(h, head) != entry:
        first = q(h, head); tp = q(h, entry + 8)
        for a, blob in ((tp, struct.pack('<Q', head)), (entry, struct.pack('<QQ', first, head)),
                        (first + 8, struct.pack('<Q', entry)), (head, struct.pack('<Q', entry))):
            k32.WriteProcessMemory(h, ctypes.c_void_p(a), blob, len(blob), ctypes.byref(ps))
    print(f'registered on {reg}  handler first {q(h, head) == entry}')

    tid = w.DWORD(0)
    th = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(TARGET), None,
                                CREATE_SUSPENDED, ctypes.byref(tid))
    c, err = get_ctx(th)
    raw = bytearray(bytes(c.buf))
    struct.pack_into('<Q', raw, RIP, TARGET)
    struct.pack_into('<I', raw, EFLAGS, struct.unpack_from('<I', raw, EFLAGS)[0] | TF)
    ctypes.memmove(ctypes.byref(c), bytes(raw), len(raw))
    put_ctx(th, c)
    k32.ResumeThread(th)
    t0 = time.time()
    while time.time() - t0 < 3.0:
        if fp.readable(h, TARGET, 4):
            break
        if not fp.alive(h):
            break
        time.sleep(0.001)
    time.sleep(0.02)
    prot = fp.prot_at(h, page)
    print(f'after fault: protection {fp.prot_name(prot[0]) if prot else None}  '
          f'alive={fp.alive(h)}')
    show('live')
    if fp.alive(h):
        lvl = rd(h, base + 0xAB7CBF0, 4)
        print('level global now =', struct.unpack('<i', lvl)[0] if lvl else None)
    ecv = w.DWORD(0)
    k32.GetExitCodeThread(th, ctypes.byref(ecv))
    if ecv.value == 259:
        k32.TerminateThread(th, 0)
    k32.CloseHandle(th)
    return 0


if __name__ == '__main__':
    sys.exit(main())

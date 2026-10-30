"""dbgrun.py - launch the rebuilt exe natively under a debug loop and report the
first faulting instruction.

The rebuilt exe runs fine under Proton but dies instantly on Windows with
"0xc0000005 at offset 0" (RIP=0), which is either a call through an unfilled IAT
slot or a bad jump out of the bootstrap. This captures the exact context:

    python dbgrun.py [seconds]

Prints every DLL the process loads (so a failed LoadLibraryA in the bootstrap is
visible), then the first-chance exception with RIP/RSP and the module that
contains it.
"""
import ctypes
import ctypes.wintypes as w
import os
import struct
import sys
import time

sys.path.insert(0, r'C:\2XKO-unpack')
from vehwalk import RIP, get_ctx

RSP = 0x98

k32 = ctypes.WinDLL('kernel32', use_last_error=True)

DEBUG_PROCESS = 0x01
DEBUG_ONLY_THIS_PROCESS = 0x02
EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
INFINITE = 0xFFFFFFFF
STILL_ACTIVE = 259

GAME = r'C:\Riot Games\2XKO_modded\Live'
EXE = os.path.join(GAME, r'Lion\Binaries\Win64\Lion-Win64-Shipping.exe')


class STARTUPINFO(ctypes.Structure):
    _fields_ = [('cb', w.DWORD), ('lpReserved', w.LPWSTR), ('lpDesktop', w.LPWSTR),
                ('lpTitle', w.LPWSTR), ('dwX', w.DWORD), ('dwY', w.DWORD),
                ('dwXSize', w.DWORD), ('dwYSize', w.DWORD),
                ('dwXCountChars', w.DWORD), ('dwYCountChars', w.DWORD),
                ('dwFillAttribute', w.DWORD), ('dwFlags', w.DWORD),
                ('wShowWindow', w.WORD), ('cbReserved2', w.WORD),
                ('lpReserved2', ctypes.POINTER(ctypes.c_byte)),
                ('hStdInput', w.HANDLE), ('hStdOutput', w.HANDLE),
                ('hStdError', w.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [('hProcess', w.HANDLE), ('hThread', w.HANDLE),
                ('dwProcessId', w.DWORD), ('dwThreadId', w.DWORD)]


class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [('ExceptionCode', w.DWORD), ('ExceptionFlags', w.DWORD),
                ('ExceptionRecord', ctypes.c_void_p), ('ExceptionAddress', ctypes.c_void_p),
                ('NumberParameters', w.DWORD),
                ('ExceptionInformation', ctypes.c_ulonglong * 15)]


class DEBUG_EVENT(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [('Exception', EXCEPTION_RECORD),
                    ('_pad', ctypes.c_byte * 160)]
    _fields_ = [('dwDebugEventCode', w.DWORD), ('dwProcessId', w.DWORD),
                ('dwThreadId', w.DWORD), ('u', _U)]


def modules(pid):
    """pid -> [(base, size, path)] using a snapshot (works on a debugged process)."""
    k32.CreateToolhelp32Snapshot.restype = w.HANDLE

    class ME(ctypes.Structure):
        _fields_ = [('dwSize', w.DWORD), ('th32ModuleID', w.DWORD),
                    ('th32ProcessID', w.DWORD), ('GlblcntUsage', w.DWORD),
                    ('ProccntUsage', w.DWORD), ('modBaseAddr', ctypes.c_void_p),
                    ('modBaseSize', w.DWORD), ('hModule', w.HMODULE),
                    ('szModule', ctypes.c_wchar * 256),
                    ('szExePath', ctypes.c_wchar * 260)]
    snap = k32.CreateToolhelp32Snapshot(0x8 | 0x10, pid)
    out = []
    if snap in (None, w.HANDLE(-1).value):
        return out
    me = ME(); me.dwSize = ctypes.sizeof(ME)
    ok = k32.Module32FirstW(snap, ctypes.byref(me))
    while ok:
        out.append((me.modBaseAddr or 0, me.modBaseSize, me.szExePath))
        ok = k32.Module32NextW(snap, ctypes.byref(me))
    k32.CloseHandle(snap)
    return out


def read(h, addr, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)):
        return None
    return buf.raw[:got.value]


def where(mods, addr):
    for base, size, path in mods:
        if base and base <= addr < base + max(size, 0x1000):
            return f'{os.path.basename(path)}+{addr - base:#x}'
    return 'NO MODULE'


def main():
    secs = float(sys.argv[1]) if len(sys.argv) > 1 else 25.0
    si = STARTUPINFO(); si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    cmd = f'"{EXE}" -disconnectedsupport-enable'
    ok = k32.CreateProcessW(EXE, ctypes.create_unicode_buffer(cmd), None, None, False,
                            DEBUG_PROCESS, None, GAME, ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        print('CreateProcess failed', ctypes.get_last_error())
        return 2
    pid = pi.dwProcessId
    print(f'pid {pid}  exe {EXE}')
    threads = {pi.dwThreadId: pi.hThread}
    t0 = time.time()
    first = None
    loaded = []
    while time.time() - t0 < secs:
        de = DEBUG_EVENT()
        if not k32.WaitForDebugEvent(ctypes.byref(de), 500):
            continue
        code = de.dwDebugEventCode
        cont = DBG_CONTINUE
        if code == CREATE_THREAD_DEBUG_EVENT:
            th = k32.OpenThread(0x1FFFFF, False, de.dwThreadId)
            if th:
                threads[de.dwThreadId] = th
        elif code == EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception
            first_chance = er.ExceptionFlags & 1 == 0
            addr = er.ExceptionAddress or 0
            mods = modules(pid)
            print(f'EXCEPTION code={er.ExceptionCode:#x} addr={addr:#x} '
                  f'({where(mods, addr)}) firstchance={first_chance} '
                  f'params={er.NumberParameters}')
            if er.ExceptionCode == 0xC0000005 and er.NumberParameters >= 2:
                print(f'  access viol at {er.ExceptionInformation[1]:#x}')
            th = threads.get(de.dwThreadId)
            if th:
                try:
                    c, _ = get_ctx(th)
                    raw = bytes(c.buf)
                    rip = struct.unpack_from('<Q', raw, RIP)[0]
                    rsp = struct.unpack_from('<Q', raw, RSP)[0]
                    print(f'  ctx rip={rip:#x} ({where(mods, rip)}) rsp={rsp:#x}')
                    regs = {'rax': 0x78, 'rcx': 0x80, 'rdx': 0x88, 'r8': 0xB8,
                            'r9': 0xC0, 'r10': 0xC8, 'r11': 0xD0}
                    print('  ' + ' '.join(f'{k}={struct.unpack_from("<Q", raw, v)[0]:#x}'
                                          for k, v in regs.items()))
                    stack = read(pi.hProcess, rsp, 0x80)
                    if stack:
                        qs = struct.unpack('<16Q', stack)
                        print('  stack: ' + ' '.join(f'{q:#x}' for q in qs[:10]))
                        for q in qs[:8]:
                            if q:
                                print(f'    ret-> {q:#x} ({where(mods, q)})')
                    exe_base = next((b for b, s, p in mods
                                     if p.lower().endswith('lion-win64-shipping.exe')), 0)
                    if exe_base:
                        boot = exe_base + 0xBEF8000
                        iat = read(pi.hProcess, boot + 0x100, 16)
                        desc = read(pi.hProcess, boot + 0x140, 40)
                        print(f'  .boot IAT: {iat.hex() if iat else None}')
                        if desc:
                            print('  import desc: ' + ' '.join(
                                f'{v:#x}' for v in struct.unpack('<5I', desc)))
                        code = read(pi.hProcess, boot, 24)
                        print(f'  .boot code: {code.hex() if code else None}')
                except Exception as e:
                    print('  ctx failed', e)
            if first:
                cont = DBG_EXCEPTION_NOT_HANDLED
            else:
                first = (er.ExceptionCode, addr)
                cont = DBG_EXCEPTION_NOT_HANDLED
        elif code == LOAD_DLL_DEBUG_EVENT:
            loaded.append(1)
        elif code == EXIT_PROCESS_DEBUG_EVENT:
            print(f'EXITED code={de.u.Exception.ExceptionCode:#x} after {time.time()-t0:.1f}s')
            print(f'dll loads seen: {len(loaded)}')
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont)

    mods = modules(pid)
    print(f'--- modules now: {len(mods)}')
    names = sorted(os.path.basename(p).lower() for _, _, p in mods if p)
    for probe in ('opencolorio_2_3.dll', 'stub.dll', 'ucrtbase.dll'):
        print(f'  {probe}: {"loaded" if probe in names else "MISSING"}')
    for base, size, path in mods[:6]:
        print(f'  {base:#x} {size:#x} {os.path.basename(path)}')

    ec = w.DWORD(0)
    if k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(ec)) and ec.value == STILL_ACTIVE:
        print('still running -> terminating')
        k32.TerminateProcess(pi.hProcess, 0)
    else:
        print(f'exit code {ec.value:#x}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

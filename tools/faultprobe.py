"""faultprobe.py - does a plain READ of a NOACCESS .text page decrypt it?

The packer under test decrypts .text one page at a time when a page is executed
(measured on Windows: 2,412 RX pages at the menu, the rest NOACCESS ciphertext).
Nobody ever tested whether a *read* fault takes the same path. If it does, all
32,784 pages can be decrypted in seconds and the unpack is finished.

    python faultprobe.py selftest
    python faultprobe.py probe  <pid|exe> [--rva HEX] [--rip-in-text]
    python faultprobe.py sweep  <pid|exe> [--chunk 256] [--start-page N]

selftest    injects the same stub into a throwaway child process whose page is
            PAGE_NOACCESS, and confirms the child dies of an access violation.
            Proves alloc/write/CreateRemoteThread work before a real launch.

probe       picks one NOACCESS page of .text (default: the largest NOACCESS run),
            makes a remote thread read one byte from it, then reports:
              - protection before / after
              - whether the page is readable now, and whether its bytes differ
                from the file on disk (i.e. were really decrypted)
              - if still unreadable, it force-enables RW for a 4 KB peek and puts
                the page back to NOACCESS, so "decrypted but still NOACCESS" is
                told apart from "still ciphertext"

sweep       repeats that over every NOACCESS page of .text in chunks, re-checking
            after each chunk, saving progress to sweep-progress.json so a dead
            process costs one chunk, not the whole run.

The stub is 24 bytes, hand-assembled and encoding-checked here:

    48 8B 19              mov rbx,[rcx]        ; start
    48 8B 51 08           mov rdx,[rcx+8]      ; end (exclusive)
    8A 03                 mov al,[rbx]         ; the read that must fault
    48 81 C3 00 10 00 00  add rbx,0x1000
    48 39 D3              cmp rbx,rdx
    72 F2                 jb  -14
    31 C0                 xor eax,eax
    C3                    ret
"""
import ctypes
import ctypes.wintypes as w
import json
import math
import os
import struct
import subprocess
import sys

PAGE = 0x1000
DISK = r'C:\Riot Games\2XKO_modded\Live\Lion\Binaries\Win64\Lion-Win64-Shipping.exe'

PROC_CREATE_THREAD = 0x0002
PROC_VM_OPERATION = 0x0008
PROC_VM_WRITE = 0x0020
PROC_VM_READ = 0x0010
PROC_QUERY_INFORMATION = 0x0400

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
WAIT_TIMEOUT = 0x102

STUB = bytes.fromhex(
    '488b19'            # mov rbx,[rcx]
    '488b5108'          # mov rdx,[rcx+8]
    '8a03'              # mov al,[rbx]      <-- faulting read
    '4881c300100000'    # add rbx,0x1000
    '4839d3'            # cmp rbx,rdx
    '72f2'              # jb  -14
    '31c0'              # xor eax,eax
    'c3'                # ret
)
assert len(STUB) == 24, len(STUB)
assert STUB[19:21] == b'\x72\xf2' and 21 - 0x0E == 7, 'loop must target the mov al,[rbx]'

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

k32.OpenProcess.restype = w.HANDLE
k32.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
k32.CloseHandle.argtypes = [w.HANDLE]
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                               w.DWORD, w.DWORD]
k32.VirtualFreeEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_size_t, w.DWORD]
k32.WriteProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualProtectEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                 w.DWORD, ctypes.POINTER(w.DWORD)]
class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', w.DWORD), ('PartitionId', w.WORD),
                ('RegionSize', ctypes.c_size_t), ('State', w.DWORD),
                ('Protect', w.DWORD), ('Type', w.DWORD)]


k32.VirtualQueryEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI),
                               ctypes.c_size_t]
k32.CreateRemoteThread.restype = w.HANDLE
k32.CreateRemoteThread.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_void_p, ctypes.c_void_p, w.DWORD,
                                   ctypes.POINTER(w.DWORD)]
k32.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
k32.GetExitCodeThread.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
k32.GetExitCodeProcess.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
psapi.EnumProcessModulesEx.argtypes = [w.HANDLE, ctypes.POINTER(w.HMODULE), w.DWORD,
                                       ctypes.POINTER(w.DWORD), w.DWORD]
psapi.GetModuleFileNameExW.argtypes = [w.HANDLE, w.HMODULE, w.LPWSTR, w.DWORD]

PROT = {0x01: 'NOACCESS', 0x02: 'R', 0x04: 'RW', 0x08: 'WC', 0x10: 'X',
        0x20: 'RX', 0x40: 'RWX', 0x80: 'WX'}


def u16(b, o): return struct.unpack_from('<H', b, o)[0]
def u32(b, o): return struct.unpack_from('<I', b, o)[0]


def prot_name(p):
    return PROT.get(p & 0xff, hex(p))


def pid_of(target):
    if target.isdigit():
        return int(target)
    out = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'],
                         capture_output=True, text=True).stdout
    exact, loose = [], []
    for line in out.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[1])
        except ValueError:
            continue
        if len(parts) > 2 and parts[2].upper() == 'N/A':   # services, skip
            continue
        if parts[0].lower() == target.lower():
            exact.append(pid)
        elif target.lower() in parts[0].lower():
            loose.append(pid)
    hits = exact or loose
    if not hits:
        raise SystemExit(f'no process matching {target!r}')
    return hits[0]


def open_target(target):
    pid = pid_of(target)
    h = k32.OpenProcess(PROC_CREATE_THREAD | PROC_VM_OPERATION | PROC_VM_WRITE
                        | PROC_VM_READ | PROC_QUERY_INFORMATION, False, pid)
    if not h:
        err = ctypes.get_last_error()
        raise SystemExit(f'OpenProcess({pid}) failed: {err}'
                         + ('  (protected process - is vgk loaded?)' if err == 5 else ''))
    return pid, h


def main_module(h):
    need = w.DWORD(0)
    arr = (w.HMODULE * 1024)()
    if not psapi.EnumProcessModulesEx(h, arr, ctypes.sizeof(arr), ctypes.byref(need), 0x03):
        raise SystemExit(f'EnumProcessModulesEx failed: {ctypes.get_last_error()}')
    best = None
    for i in range(need.value // ctypes.sizeof(w.HMODULE)):
        buf = ctypes.create_unicode_buffer(1024)
        psapi.GetModuleFileNameExW(h, arr[i], buf, 1024)
        size = os.path.getsize(buf.value) if os.path.exists(buf.value) else 0
        cand = (size, ctypes.cast(arr[i], ctypes.c_void_p).value, buf.value)
        if best is None or cand[0] > best[0]:
            best = cand
    return best[1], best[2]


def sections_of(exe):
    d = open(exe, 'rb').read(0x2000)
    pe = u32(d, 0x3c)
    nsec, optsz = u16(d, pe + 6), u16(d, pe + 20)
    so = pe + 24 + optsz
    out = {}
    for i in range(nsec):
        o = so + i * 40
        out[d[o:o + 8].rstrip(b'\0').decode('latin1')] = {
            'va': u32(d, o + 12), 'vsz': u32(d, o + 8),
            'raw': u32(d, o + 20), 'chars': u32(d, o + 36)}
    return out


def prot_at(h, addr):
    mbi = MBI()
    if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        return None
    return mbi.Protect, mbi.State


def readable(h, addr, n=16):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got))
    return ok and got.value == n


def read_bytes(h, addr, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)):
        return None
    return buf.raw[:got.value]


def force_read(h, addr, n):
    """Read n bytes, temporarily granting RW if needed. Returns (data, granted)."""
    if readable(h, addr, min(n, 16)):
        return read_bytes(h, addr, n), False
    old = w.DWORD(0)
    if not k32.VirtualProtectEx(h, ctypes.c_void_p(addr), n, PAGE_READWRITE,
                                ctypes.byref(old)):
        return None, False
    data = read_bytes(h, addr, n)
    cur = w.DWORD(0)
    k32.VirtualProtectEx(h, ctypes.c_void_p(addr), n, PAGE_NOACCESS, ctypes.byref(cur))
    return data, True


def entropy(b):
    if not b:
        return 0.0
    c = [0] * 256
    for x in b:
        c[x] += 1
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c if v)


def run_stub(h, start, end, in_text_host=None):
    """Run the read-loop stub over [start, end). Returns (waited, exit_code)."""
    code = ctypes.c_void_p(k32.VirtualAllocEx(h, None, 0x1000,
                                             MEM_COMMIT | MEM_RESERVE,
                                             PAGE_EXECUTE_READWRITE))
    if not code:
        raise SystemExit(f'VirtualAllocEx(code) failed: {ctypes.get_last_error()}')
    param = ctypes.c_void_p(k32.VirtualAllocEx(h, None, 0x1000,
                                              MEM_COMMIT | MEM_RESERVE,
                                              PAGE_READWRITE))
    if not param:
        raise SystemExit(f'VirtualAllocEx(param) failed: {ctypes.get_last_error()}')

    target_code = code
    if in_text_host:
        old = w.DWORD(0)
        if not k32.VirtualProtectEx(h, ctypes.c_void_p(in_text_host), PAGE, PAGE_EXECUTE_READWRITE,
                                    ctypes.byref(old)):
            raise SystemExit(f'VirtualProtectEx(text host) failed: {ctypes.get_last_error()}')
        target_code = ctypes.c_void_p(in_text_host)

    wrote = ctypes.c_size_t(0)
    if not k32.WriteProcessMemory(h, target_code, STUB, len(STUB), ctypes.byref(wrote)):
        raise SystemExit(f'WriteProcessMemory(stub) failed: {ctypes.get_last_error()}')
    if not k32.WriteProcessMemory(h, param, struct.pack('<QQ', start, end), 16,
                                  ctypes.byref(wrote)):
        raise SystemExit(f'WriteProcessMemory(param) failed: {ctypes.get_last_error()}')

    tid = w.DWORD(0)
    th = k32.CreateRemoteThread(h, None, 0, target_code, param, 0, ctypes.byref(tid))
    if not th:
        raise SystemExit(f'CreateRemoteThread failed: {ctypes.get_last_error()}')
    waited = k32.WaitForSingleObject(th, 10000)
    exit_code = w.DWORD(0)
    k32.GetExitCodeThread(th, ctypes.byref(exit_code))
    k32.CloseHandle(th)
    if not in_text_host:
        k32.VirtualFreeEx(h, code, 0, 0x8000)
    k32.VirtualFreeEx(h, param, 0, 0x8000)
    return waited, exit_code.value


def probe_one(h, base, va, off, disk, doff, rip_in_text=None):
    page = base + va + off
    before = prot_at(h, page)
    was_readable = readable(h, page)
    waited, code = run_stub(h, page, page + PAGE,
                            in_text_host=(base + rip_in_text) if rip_in_text else None)
    after = prot_at(h, page)
    now_readable = readable(h, page)

    data, forced = (read_bytes(h, page, PAGE), False) if now_readable else force_read(h, page, PAGE)
    diskpage = disk[doff + off:doff + off + PAGE]
    differs = None if data is None else (data != diskpage)
    ent = entropy(data) if data else None

    return {
        'page_rva': va + off,
        'page_va': page,
        'prot_before': prot_name(before[0]) if before else '?',
        'readable_before': was_readable,
        'wait_result': 'signalled' if waited == 0 else ('timeout' if waited == WAIT_TIMEOUT else waited),
        'thread_exit': code,
        'prot_after': prot_name(after[0]) if after else 'NO-PROCESS',
        'readable_after': now_readable,
        'peek_forced_rw': forced,
        'differs_from_disk': differs,
        'entropy': round(ent, 3) if ent is not None else None,
        'first_bytes': data[:16].hex() if data else None,
        'disk_first_bytes': diskpage[:16].hex(),
        'disk_entropy': round(entropy(diskpage), 3),
    }


def alive(h):
    code = w.DWORD(0)
    if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
        return False
    return code.value == 259          # STILL_ACTIVE


def cmd_selftest():
    child_src = (
        'import ctypes, time\n'
        'k32 = ctypes.WinDLL("kernel32")\n'
        'k32.VirtualAlloc.restype = ctypes.c_void_p\n'
        'addr = k32.VirtualAlloc(None, 0x1000, 0x3000, 0x04)\n'
        'old = ctypes.c_ulong(0)\n'
        'k32.VirtualProtect(ctypes.c_void_p(addr), 0x1000, 0x01, ctypes.byref(old))\n'
        'print(hex(addr), flush=True)\n'
        'time.sleep(30)\n'
    )
    p = subprocess.Popen([sys.executable, '-c', child_src],
                         stdout=subprocess.PIPE, text=True)
    try:
        addr = int(p.stdout.readline().strip(), 16)
    except ValueError:
        p.kill()
        raise SystemExit('child did not report its page address')
    print(f'child pid {p.pid}, NOACCESS page {addr:#x}')
    h = k32.OpenProcess(PROC_CREATE_THREAD | PROC_VM_OPERATION | PROC_VM_WRITE
                        | PROC_VM_READ | PROC_QUERY_INFORMATION, False, p.pid)
    if not h:
        p.kill()
        raise SystemExit(f'OpenProcess(child) failed: {ctypes.get_last_error()}')
    print('protection before:', prot_name(prot_at(h, addr)[0]))
    waited, code = run_stub(h, addr, addr + PAGE)
    print(f'stub wait={waited} exit={code}  child alive={alive(h)}')
    rc = p.wait(timeout=10)
    print(f'child exit code: {rc}  ({hex(rc & 0xffffffff)})')
    ok = (rc != 0) and (waited == 0)
    print('\nSELFTEST ' + ('PASS' if ok else 'FAIL')
          + ': the stub does raise an access violation in a NOACCESS page')
    return 0 if ok else 1


def cmd_probe(argv):
    in_text = '--rip-in-text' in argv
    argv = [a for a in argv if a != '--rip-in-text']
    target = argv[0]
    rva = None
    for i, a in enumerate(argv):
        if a == '--rva':
            rva = int(argv[i + 1], 0)

    pid, h = open_target(target)
    base, path = main_module(h)
    secs = sections_of(DISK)
    t = secs['.text']
    disk = open(DISK, 'rb').read()
    print(f'pid {pid}  module {path}')
    print(f'base {base:#x}  .text va {t["va"]:#x} size {t["vsz"]:#x} chars {t["chars"]:#x}')

    # find a NOACCESS page: either the requested RVA, or the biggest NOACCESS run
    if rva is not None:
        off = rva - t['va']
    else:
        best = (0, 0)               # (size, start_off)
        run_start, run_len = None, 0
        addr = base + t['va']
        for off in range(0, t['vsz'], PAGE):
            p = prot_at(h, addr + off)
            if p and (p[0] & 0xff) == PAGE_NOACCESS:
                if run_start is None:
                    run_start, run_len = off, 0
                run_len += PAGE
            else:
                if run_start is not None and run_len > best[0]:
                    best = (run_len, run_start)
                run_start = None
        if run_start is not None and run_len > best[0]:
            best = (run_len, run_start)
        if best[0] == 0:
            raise SystemExit('no NOACCESS run found in .text - wrong process state?')
        # aim at the middle of the biggest run, page-aligned
        off = best[1] + (best[0] // 2 // PAGE) * PAGE
        print(f'biggest NOACCESS run: {best[1] + t["va"]:#x} + {best[0] / 1048576:.2f} MB '
              f'-> probing {off + t["va"]:#x}')

    rip_host = None
    if in_text:
        # put the stub inside an already-decrypted (RX) page of .text instead
        addr = base + t['va']
        for o in range(0, t['vsz'], PAGE):
            p = prot_at(h, addr + o)
            if p and (p[0] & 0xff) == PAGE_EXECUTE_READ:
                rip_host = t['va'] + o + 0x800
                print(f'stub host inside .text at rva {rip_host:#x} (page {t["va"] + o:#x})')
                break
        if rip_host is None:
            raise SystemExit('no RX page found to host the stub inside .text')

    res = probe_one(h, base, t['va'], off, disk, t['raw'], rip_in_text=rip_host)
    for k, v in res.items():
        print(f'  {k:<20} {v}')
    print(f'  process alive        {alive(h)}')
    print(f'  NOACCESS pages left  {sum(1 for o in range(0, t["vsz"], PAGE) if (prot_at(h, base + t["va"] + o) or (0,))[0] & 0xff == PAGE_NOACCESS):,}')

    print('\n--- verdict ---')
    if res['differs_from_disk'] and res['thread_exit'] in (0,):
        print('READ FAULT DECRYPTS: the page is no longer ciphertext and the thread finished cleanly.')
        print('-> run: python faultprobe.py sweep <target>')
    elif res['differs_from_disk']:
        print('Page bytes differ from disk, but the thread did not exit cleanly - inspect exit code.')
    elif res['differs_from_disk'] is False:
        print('NO DECRYPTION: the page is still byte-identical to the ciphertext on disk.')
        if not alive(h):
            print('The process died on the read fault -> the handler rejects reads outright.')
        elif res['peek_forced_rw']:
            print('Page was still NOACCESS afterwards (forced RW for the peek): the handler ignored the read.')
        else:
            print('Page changed protection but the bytes are unchanged: protection games only.')
    else:
        print('INCONCLUSIVE: could not read the page even after forcing RW.')
    return 0


def cmd_sweep(argv):
    target = argv[0]
    chunk = 256
    start_page = 0
    for i, a in enumerate(argv):
        if a == '--chunk':
            chunk = int(argv[i + 1])
        if a == '--start-page':
            start_page = int(argv[i + 1])

    pid, h = open_target(target)
    base, path = main_module(h)
    t = sections_of(DISK)['.text']
    npages = (t['vsz'] + PAGE - 1) // PAGE
    print(f'pid {pid} base {base:#x}  {npages:,} pages, chunk {chunk}, from page {start_page}')

    progress_path = r'C:\2XKO-unpack\sweep-progress.json'
    done = set()
    if os.path.exists(progress_path):
        try:
            done = set(json.load(open(progress_path))['decrypted_pages'])
        except Exception:
            done = set()

    addr0 = base + t['va']
    todo = [o for o in range(0, npages) if o >= start_page
            and o * PAGE not in done
            and (prot_at(h, addr0 + o * PAGE) or (0,))[0] & 0xff == PAGE_NOACCESS]
    print(f'{len(todo):,} NOACCESS pages to try')

    for i in range(0, len(todo), chunk):
        group = todo[i:i + chunk]
        start = addr0 + group[0] * PAGE
        end = addr0 + (group[-1] + 1) * PAGE
        waited, code = run_stub(h, start, end)
        decrypted = [o for o in group if readable(h, addr0 + o * PAGE)]
        for o in decrypted:
            done.add(o * PAGE)
        json.dump({'decrypted_pages': sorted(done)}, open(progress_path, 'w'))
        print(f'  pages {group[0]:,}-{group[-1]:,}  wait={waited} exit={code}  '
              f'decrypted now {len(decrypted)}/{len(group)}  total {len(done):,}/{npages:,}')
        if not alive(h):
            print(f'PROCESS DIED at page {group[0]:,} (rva {(t["va"] + group[0] * PAGE):#x})')
            print(f'progress saved: {len(done):,} pages decrypted')
            return 2
        if len(decrypted) < len(group):
            print('  partial: some pages in the chunk did not decrypt - stopping')
            return 2

    print(f'\nDONE: {len(done):,} of {npages:,} pages readable')
    return 0


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    cmd = sys.argv[1]
    if cmd == 'selftest':
        return cmd_selftest()
    if cmd == 'probe':
        return cmd_probe(sys.argv[2:])
    if cmd == 'sweep':
        return cmd_sweep(sys.argv[2:])
    raise SystemExit(__doc__)


if __name__ == '__main__':
    sys.exit(main())

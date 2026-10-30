"""tfwalk.py - decrypt a page, then trap after exactly one instruction.

The last crash settled it: 0xC0000409 at .text+0x7e68ec5, i.e. a thread started
at a function entry ran about 2 MB into decrypted code and hit a __fastfail.
Suspend/terminate from outside is too late - the page turns readable and the
thread is already running.

So the trap has to be in place before the thread runs:

    create suspended at a RUNTIME_FUNCTION begin address
    set RIP = entry, EFLAGS.TF = 1
    resume  -> fetch faults -> packer decrypts -> does NOT handle it first,
               our handler returns EXCEPTION_CONTINUE_SEARCH for the AV
    -> packer decrypts and resumes
    -> one instruction executes -> #DB
    -> our handler sees STATUS_SINGLE_STEP, points RIP at a `jmp $` stub and
       returns EXCEPTION_CONTINUE_EXECUTION -> thread parked, page dumped

The handler and its counters live in the same page (RIP-relative), so the
counters cannot be blamed on a separate data page. It handles ONLY single-step;
every other exception is passed through untouched, which is what lets the packer
do the decryption.

    python tfwalk.py <pid|exe> [--start 6000] [--pages 50]
"""
import ctypes
import ctypes.wintypes as w
import os
import os
import struct
import sys
import time

sys.path.insert(0, r'C:\2XKO-unpack')
import faultprobe as fp
from vehwalk import RIP, EFLAGS, TF, CREATE_SUSPENDED, get_ctx, put_ctx, ctx_fields
from vehtest import build_register2
from pdatawalk import page_entries, load_state, save, save_page
from pe_dis import PEfile

PAGE = 0x1000
OUT = r'C:\2XKO-unpack\textdump'
STATUS_SINGLE_STEP = 0x80000004
k32 = fp.k32
k32.TerminateThread.argtypes = [w.HANDLE, w.DWORD]
HANDLE_SLOT = 0x1A0
NEXT_FILE = r"C:\2XKO-unpack\textdump\next.txt"

CPU = dict(RED=0x400, LAST=0x408, CODE=0x410, SAFE=0x100)


def build_handler(code):
    """Handles only STATUS_SINGLE_STEP; everything else is passed through."""
    b = bytearray()
    fix = []
    labels = {}

    def emit_rip(op, target):
        start = len(b)
        b.extend(op)
        b.extend(struct.pack('<i', target - (code + start + len(op) + 4)))

    def mark(name):
        labels[name] = len(b)

    emit_rip(b'\x48\x8b\x11', 0) if False else b.extend(b'\x48\x8b\x11')  # mov rdx,[rcx]
    b.extend(b'\x8b\x02')                                     # mov eax,[rdx]
    emit_rip(b'\x89\x05', code + CPU['CODE'])                 # mov [rip+CODE],eax
    b.extend(b'\x3d' + struct.pack('<I', STATUS_SINGLE_STEP))  # cmp eax,SINGLE_STEP
    b.extend(b'\x75\x00')
    fix.append((len(b) - 1, 'pass'))
    emit_rip(b'\xff\x05', code + CPU['RED'])                  # inc dword [rip+RED]
    b.extend(b'\x48\x8b\x51\x08')                             # mov rdx,[rcx+8]
    b.extend(b'\x48\x8b\x82' + struct.pack('<I', RIP))        # mov rax,[rdx+Rip]
    emit_rip(b'\x48\x89\x05', code + CPU['LAST'])             # mov [rip+LAST],rax
    b.extend(b'\xc7\x82' + struct.pack('<I', EFLAGS) + struct.pack('<I', 0x202))
    emit_rip(b'\x48\x8d\x05', code + CPU['SAFE'])             # lea rax,[rip+SAFE]
    b.extend(b'\x48\x89\x82' + struct.pack('<I', RIP))        # mov [rdx+Rip],rax
    b.extend(b'\xb8\xff\xff\xff\xff')                         # mov eax,-1
    b.extend(b'\xc3')
    mark('pass')
    b.extend(b'\x31\xc0')
    b.extend(b'\xc3')
    for at, lab in fix:
        b[at] = (labels[lab] - (at + 1)) & 0xff
    return bytes(b)


def q(h, a):
    return struct.unpack_from('<Q', fp.read_bytes(h, a, 8) or bytes(8), 0)[0]


def d(h, a):
    return struct.unpack_from('<I', fp.read_bytes(h, a, 4) or bytes(4), 0)[0]


def find_host(h):
    """A zero-filled, committed page in another module's writable BSS."""
    arr = (w.HMODULE * 1024)()
    need = w.DWORD(0)
    fp.psapi.EnumProcessModulesEx(h, arr, ctypes.sizeof(arr), ctypes.byref(need), 0x03)
    mods = []
    for i in range(need.value // ctypes.sizeof(w.HMODULE)):
        buf = ctypes.create_unicode_buffer(1024)
        fp.psapi.GetModuleFileNameExW(h, arr[i], buf, 1024)
        mods.append((ctypes.cast(arr[i], ctypes.c_void_p).value, buf.value))
    mods.sort(key=lambda m: -(os.path.getsize(m[1]) if os.path.exists(m[1]) else 0))
    tried = 0
    for base, path in mods:
        if not os.path.exists(path) or not path.lower().endswith(('.dll', '.exe')):
            continue
        if os.path.normcase(path) == os.path.normcase(fp.DISK):
            continue
        try:
            p = PEfile(path)
        except Exception:
            continue
        for s in p.sections:
            if not (s['chars'] & 0x80000000) or s['vsz'] <= s['rawsz']:
                continue
            page = ((base + s['va'] + s['vsz']) & ~0xFFF) - PAGE
            lo = base + s['va']
            fails = 0
            while page > lo and tried < 400 and fails < 4:
                tried += 1
                mbi = fp.prot_at(h, page)
                if not mbi or (mbi[0] & 0xff) == fp.PAGE_NOACCESS:
                    fails += 1
                    page -= PAGE
                    continue
                blob = fp.read_bytes(h, page, PAGE)
                if blob is None or blob.count(0) != PAGE:
                    fails += 1
                    page -= PAGE
                    continue
                return page
    return None


def main():
    pid, h = fp.open_target(sys.argv[1])
    base, path = fp.main_module(h)
    per, text = page_entries()
    vsz = text['vsz']
    addr0 = base + text['va']
    npages = (vsz + PAGE - 1) // PAGE
    start, want = 0, 50
    for i, a in enumerate(sys.argv):
        if a == '--start':
            start = int(sys.argv[i + 1])
        if a == '--pages':
            want = int(sys.argv[i + 1])

    k32.GetModuleHandleW.restype = ctypes.c_void_p
    k32.GetProcAddress.restype = ctypes.c_void_p
    k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    aveh = k32.GetProcAddress(k32.GetModuleHandleW('kernel32'),
                              b'AddVectoredExceptionHandler')
    code = find_host(h)
    if not code:
        print('no usable image page host found')
        return 2
    _old = w.DWORD(0)
    if not k32.VirtualProtectEx(h, ctypes.c_void_p(code), 0x1000, 0x40, ctypes.byref(_old)):
        print(f'VirtualProtectEx(host) failed err {ctypes.get_last_error()}')
        return 2
    print(f'host page {code:#x} (image BSS)')
    for off in (0, 0x100, 0x300, 0x400):
        fp.k32.WriteProcessMemory(h, ctypes.c_void_p(code + off), bytes(16), 16,
                                  ctypes.byref(ctypes.c_size_t(0)))
    handler = build_handler(code)
    ok = fp.k32.WriteProcessMemory(h, ctypes.c_void_p(code), handler, len(handler),
                                   ctypes.byref(ctypes.c_size_t(0)))
    fp.k32.WriteProcessMemory(h, ctypes.c_void_p(code + CPU['SAFE']), b'\xeb\xfe', 2,
                              ctypes.byref(ctypes.c_size_t(0)))
    reg_stub = build_register2(aveh, code, code + HANDLE_SLOT)
    fp.k32.WriteProcessMemory(h, ctypes.c_void_p(code + 0x300), reg_stub,
                              len(reg_stub),
                              ctypes.byref(ctypes.c_size_t(0)))
    print(f'pid {pid}  code {code:#x}  handler {len(handler)} bytes  write={bool(ok)}')
    print(f'handler: {handler.hex()}')

    reg = None
    for attempt in range(1, 1201):
        if not fp.alive(h):
            print('died while registering')
            return 2
        tid = w.DWORD(0)
        th = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(code + 0x300), None,
                                    0, ctypes.byref(tid))
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
        print('registration never ran')
        return 2
    entry = q(h, code + HANDLE_SLOT)
    head = None
    arr = (w.HMODULE * 1024)()
    need = w.DWORD(0)
    fp.psapi.EnumProcessModulesEx(h, arr, ctypes.sizeof(arr), ctypes.byref(need), 0x03)
    for i in range(need.value // ctypes.sizeof(w.HMODULE)):
        buf = ctypes.create_unicode_buffer(1024)
        fp.psapi.GetModuleFileNameExW(h, arr[i], buf, 1024)
        if buf.value.lower().endswith('ntdll.dll'):
            head = ctypes.cast(arr[i], ctypes.c_void_p).value + 0x1EB580
    fp.ntdll = ctypes.WinDLL('ntdll')
    fp.ntdll.NtQueryInformationProcess.argtypes = [w.HANDLE, ctypes.c_int,
                                                   ctypes.c_void_p, w.ULONG,
                                                   ctypes.POINTER(w.ULONG)]
    buf = ctypes.create_string_buffer(0x30)
    ret = w.ULONG(0)
    fp.ntdll.NtQueryInformationProcess(h, 0, buf, 0x30, ctypes.byref(ret))
    peb = struct.unpack_from('<Q', buf.raw, 8)[0]
    print(f'peb {peb:#x}  veh bit {bool(d(h, peb + 0x50) & 4)}')
    old = w.DWORD(0)
    fp.k32.VirtualProtectEx(h, ctypes.c_void_p(head), 0x1000, 0x04, ctypes.byref(old))
    first = q(h, head)
    if first != entry:
        tail_prev = q(h, entry + 8)          # entry that currently precedes ours
        fp.k32.WriteProcessMemory(h, ctypes.c_void_p(tail_prev),
                                  struct.pack('<Q', head), 8,
                                  ctypes.byref(ctypes.c_size_t(0)))
        fp.k32.WriteProcessMemory(h, ctypes.c_void_p(entry),
                                  struct.pack('<QQ', first, head), 16,
                                  ctypes.byref(ctypes.c_size_t(0)))
        fp.k32.WriteProcessMemory(h, ctypes.c_void_p(first + 8),
                                  struct.pack('<Q', entry), 8,
                                  ctypes.byref(ctypes.c_size_t(0)))
        fp.k32.WriteProcessMemory(h, ctypes.c_void_p(head),
                                  struct.pack('<Q', entry), 8,
                                  ctypes.byref(ctypes.c_size_t(0)))
    print(f'registered on attempt {reg}  entry {entry:#x}  '
          f'first={q(h, head):#x}  (others kept: the packer must decrypt)')

    dumped = load_state(npages, vsz)
    todo = [i for i in range(npages) if not dumped[i] and i >= start and i in per]
    print(f'{len(todo)} candidate pages from {start}')

    ok_n = dead_n = 0
    last_done = start - 1

    def save_next(idx):
        try:
            open(NEXT_FILE, 'w').write(str(idx))
        except OSError:
            pass

    t0 = time.time()
    for n, i in enumerate(todo[:want], 1):
        if not fp.alive(h):
            print('process died')
            break
        addr = addr0 + i * PAGE
        off = i * PAGE
        nbytes = min(PAGE, vsz - off)
        if fp.readable(h, addr, 4):
            data = fp.read_bytes(h, addr, nbytes)
            if data:
                save_page(off, data)
                dumped[i] = 1
                ok_n += 1
            continue
        entries = per[i][:3]
        got = False
        for e in entries:
            red0 = d(h, code + CPU['RED'])
            tid = w.DWORD(0)
            th = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(base + e), None,
                                        CREATE_SUSPENDED, ctypes.byref(tid))
            if not th:
                break
            c, err = get_ctx(th)
            if c is None:
                k32.CloseHandle(th)
                break
            raw = bytearray(bytes(c.buf))
            struct.pack_into('<Q', raw, RIP, base + e)
            struct.pack_into('<I', raw, EFLAGS,
                             struct.unpack_from('<I', raw, EFLAGS)[0] | TF)
            ctypes.memmove(ctypes.byref(c), bytes(raw), len(raw))
            put_ctx(th, c)
            k32.ResumeThread(th)
            t1 = time.time()
            while time.time() - t1 < 0.3:
                if fp.readable(h, addr, 4):
                    got = True
                    break
                if not fp.alive(h):
                    break
                pass  # busy-wait: Windows sleep granularity is 1-15 ms
            ecv = w.DWORD(0)
            k32.GetExitCodeThread(th, ctypes.byref(ecv))
            if d(h, code + CPU['RED']) > red0:
                k32.TerminateThread(th, 0)      # parked in our own stub: safe
            elif ecv.value == 259:
                k32.SuspendThread(th)
            k32.CloseHandle(th)
            if got or not fp.alive(h):
                break
        if got:
            data = fp.read_bytes(h, addr, nbytes)
            if data:
                save_page(off, data)
                dumped[i] = 1
                ok_n += 1
        if not fp.alive(h):
            print(f'  page {n} (rva {text["va"] + i * PAGE:#x}): PROCESS DIED')
            break
        last_done = i
        if n % 10 == 0:
            save(dumped)
            save_next(i + 1)
            print(f'  {n}/{min(want, len(todo))}  {ok_n} dumped  '
                  f'red={d(h, code + CPU["RED"])}  '
                  f'last_rip={q(h, code + CPU["LAST"]):#x}  '
                  f'{n / (time.time() - t0):5.1f}/s  alive={fp.alive(h)}', flush=True)
    save(dumped)
    save_next((last_done + 1) if last_done >= 0 else start)
    print(f'\n{ok_n} dumped  total {sum(dumped)}/{npages}  '
          f'handler hits={d(h, code + CPU["RED"]) if fp.alive(h) else "n/a"}  '
          f'alive={fp.alive(h)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

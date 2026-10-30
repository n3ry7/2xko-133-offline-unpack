"""findoep2.py - the OEP is the first .text instruction to fault.

In a fresh process every .text page is NOACCESS, so the very first instruction the
packer jumps to faults there. Our vectored handler runs before the packer's (we move
ours to the front), so it can record that first faulting RIP exactly - no sampling,
no missing it.

Records the first STATUS_ACCESS_VIOLATION whose RIP is inside .text, then lets every
exception through so the packer still does its job.

    python findoep2.py <pid|exe>
"""
import ctypes
import ctypes.wintypes as w
import struct
import sys
import time

sys.path.insert(0, r'C:\2XKO-unpack')
import faultprobe as fp
from vehwalk import RIP, EFLAGS, PAGE, rd, wr
from vehtest import build_register2
from tfwalk6 import find_host, CPU
from pdatawalk import page_entries

k32 = fp.k32
HANDLE_SLOT = 0x1A0
SLOT = 0x500          # first .text AV rip
C_AV_REC = 0x508      # number of .text AVs seen


def q(h, a):
    return struct.unpack_from('<Q', fp.read_bytes(h, a, 8) or bytes(8), 0)[0]


def main():
    pid, h = fp.open_target(sys.argv[1])
    base, _ = fp.main_module(h)
    print('waiting 8 s for the module set to settle ...')
    time.sleep(8)
    t = fp.sections_of(fp.DISK)['.text']
    addr0 = base + t['va']
    lo, hi = addr0, addr0 + t['vsz']
    print(f'pid {pid}  .text {lo:#x}..{hi:#x}')

    k32.GetModuleHandleW.restype = ctypes.c_void_p
    k32.GetProcAddress.restype = ctypes.c_void_p
    k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    aveh = k32.GetProcAddress(k32.GetModuleHandleW('kernel32'),
                              b'AddVectoredExceptionHandler')

    code = find_host(h)
    if not code:
        print('no host page'); return 2
    # which module owns the host page?
    arr0 = (w.HMODULE * 1024)(); need0 = w.DWORD(0)
    fp.psapi.EnumProcessModulesEx(h, arr0, ctypes.sizeof(arr0), ctypes.byref(need0), 0x03)
    owner = '?'
    for i in range(need0.value // ctypes.sizeof(w.HMODULE)):
        b0 = ctypes.cast(arr0[i], ctypes.c_void_p).value
        if b0 <= code:
            buf0 = ctypes.create_unicode_buffer(1024)
            fp.psapi.GetModuleFileNameExW(h, arr0[i], buf0, 1024)
            owner = buf0.value
    print(f'host page {code:#x} in {owner}')
    old = w.DWORD(0)
    k32.VirtualProtectEx(h, ctypes.c_void_p(code), PAGE, 0x40, ctypes.byref(old))
    ps = ctypes.c_size_t(0)

    # handler: record the first AV whose RIP is in .text; pass everything through
    b = bytearray()

    def emit(x):
        b.extend(x)

    def rip_disp(target):
        # displacement for a 32-bit rip-relative operand at the current position
        # (call sites below put the disp right after a 3-byte opcode)
        return target - (code + len(b) + 4)

    emit(b'\x48\x8b\x11')                                   # mov rdx,[rcx]
    emit(b'\x8b\x02')                                       # mov eax,[rdx]
    emit(b'\x3d' + struct.pack('<I', 0xC0000005))           # cmp eax,AV
    # jne pass
    b.extend(b'\x75\x00')
    jne_at = len(b) - 1
    emit(b'\x48\x8b\x51\x08')                               # mov rdx,[rcx+8]
    emit(b'\x48\x8b\x82' + struct.pack('<I', RIP))          # mov rax,[rdx+Rip]
    emit(b'\x49\xb8' + struct.pack('<Q', code + SLOT))      # mov r8,slot
    emit(b'\x49\x83\x38\x00')                               # cmp qword [r8],0
    b.extend(b'\x75\x00')
    jne2_at = len(b) - 1
    emit(b'\x49\xb9' + struct.pack('<Q', lo))               # mov r9,text_lo
    emit(b'\x4c\x39\xc8')                                   # cmp rax,r9
    b.extend(b'\x72\x00')
    jb_at = len(b) - 1
    emit(b'\x49\xb9' + struct.pack('<Q', hi))               # mov r9,text_hi
    emit(b'\x4c\x39\xc8')
    b.extend(b'\x73\x00')
    jae_at = len(b) - 1
    emit(b'\x49\x89\x00')                                   # mov [r8],rax
    emit(b'\x49\xb8' + struct.pack('<Q', code + C_AV_REC))
    emit(b'\x41\xff\x00')                                   # inc dword [r8]
    pass_at = len(b)
    emit(b'\x31\xc0\xc3')                                   # xor eax,eax; ret
    for at in (jne_at, jne2_at, jb_at, jae_at):
        b[at] = (pass_at - (at + 1)) & 0xff

    handler = bytes(b)
    k32.WriteProcessMemory(h, ctypes.c_void_p(code), handler, len(handler), ctypes.byref(ps))
    stub = build_register2(aveh, code, code + HANDLE_SLOT)
    k32.WriteProcessMemory(h, ctypes.c_void_p(code + 0x300), stub, len(stub), ctypes.byref(ps))
    print(f'host {code:#x}  handler {len(handler)} bytes')

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
    print(f'registered on attempt {reg}')

    # move ours to the front of the VEH list
    ntdll = None
    arr = (w.HMODULE * 1024)(); need = w.DWORD(0)
    fp.psapi.EnumProcessModulesEx(h, arr, ctypes.sizeof(arr), ctypes.byref(need), 0x03)
    for i in range(need.value // ctypes.sizeof(w.HMODULE)):
        buf = ctypes.create_unicode_buffer(1024)
        fp.psapi.GetModuleFileNameExW(h, arr[i], buf, 1024)
        if buf.value.lower().endswith('ntdll.dll'):
            ntdll = ctypes.cast(arr[i], ctypes.c_void_p).value
    head = ntdll + 0x1EB580
    entry = q(h, code + HANDLE_SLOT)
    k32.VirtualProtectEx(h, ctypes.c_void_p(head), PAGE, 0x04, ctypes.byref(old))
    if q(h, head) != entry:
        first = q(h, head); tp = q(h, entry + 8)
        for a, blob in ((tp, struct.pack('<Q', head)),
                        (entry, struct.pack('<QQ', first, head)),
                        (first + 8, struct.pack('<Q', entry)),
                        (head, struct.pack('<Q', entry))):
            k32.WriteProcessMemory(h, ctypes.c_void_p(a), blob, len(blob), ctypes.byref(ps))
    print(f'handler first: {q(h, head) == entry}')

    # wait for the packer to reach the OEP
    t0 = time.time()
    last = None
    while time.time() - t0 < 90:
        if not fp.alive(h):
            print('process died'); break
        v = q(h, code + SLOT)
        c = struct.unpack_from('<I', fp.read_bytes(h, code + C_AV_REC, 4) or bytes(4), 0)[0]
        if (v, c) != last:
            print(f'  t={time.time() - t0:5.1f}s  first .text AV rip={v:#x}  count={c}')
            last = (v, c)
        if v:
            break
        time.sleep(0.05)

    v = q(h, code + SLOT)
    if v:
        rva = v - base
        per, text = page_entries()
        # enclosing function from .pdata
        import pe_dis
        p = pe_dis.PEfile(fp.DISK)
        pd = [s for s in p.sections if s['name'] == '.pdata'][0]
        body = p.d[pd['raw']:pd['raw'] + pd['vsz']]
        fn = None
        for i in range(len(body) // 12):
            bb, ee, uu = struct.unpack_from('<III', body, i * 12)
            if bb <= rva < ee:
                fn = (bb, ee)
                break
        print(f'\nOEP candidate: rip {v:#x}  rva {rva:#x}  '
              + (f'function {fn[0]:#x}..{fn[1]:#x}' if fn else '(no .pdata function)'))
    else:
        print('\nno .text access violation observed')
    return 0


if __name__ == '__main__':
    sys.exit(main())

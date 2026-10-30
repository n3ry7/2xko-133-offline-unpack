"""vehtest.py - is my vectored exception handler actually in the chain, and
does it come before the packer's?

vehdiag.py decrypted a page in 0.9 ms while my handler counted no exceptions at
all (av=0 db=0). Two explanations: the packer handles the fault before my
handler, or my handler was never registered (the return value of
AddVectoredExceptionHandler was ignored).

This settles it without guessing:

  1. the registration stub stores the handle AddVectoredExceptionHandler returns
     into our data page, so success/failure is visible
  2. an int3 stub  (0xCC)         -> STATUS_BREAKPOINT
     an AV stub    (write to 0x10) -> STATUS_ACCESS_VIOLATION
     the handler redirects any exception whose RIP is inside our own code page
     to a safe stub that exits 0x5A5A, and passes everything else through

    handler reachable  -> the stub's thread exits 0x5A5A
    handler not there  -> the exception is unhandled and the process dies
                          (or the packer swallows it and the thread exits 0)

    python vehtest.py <pid|exe>
"""
import ctypes
import ctypes.wintypes as w
import struct
import sys

sys.path.insert(0, r'C:\2XKO-unpack')
import faultprobe as fp
from vehwalk import (RIP, EFLAGS, build_safe, ctx_fields, rd, run_once, wr)

STATUS_BREAKPOINT = 0x80000003
STATUS_SINGLE_STEP = 0x80000004
STATUS_AV = 0xC0000005
HANDLE_SLOT = 0x1A0


def build_handler3(code_lo, code_hi, text_lo, text_hi, safe_addr, data):
    b = bytearray()
    fix = []
    labels = {}

    def emit(x):
        b.extend(x)

    def rel8(op, label):
        emit(op)
        fix.append((len(b), label))
        emit(b'\x00')

    def mark(label):
        labels[label] = len(b)

    emit(b'\x48\x8b\x11')                                     # mov rdx,[rcx]
    emit(b'\x8b\x02')                                         # mov eax,[rdx]
    emit(b'\x49\xb8' + struct.pack('<Q', data + 0x1B0))
    emit(b'\x89\x00')                                         # [data+0x1B0]=code
    emit(b'\x48\x8b\x51\x08')                                 # mov rdx,[rcx+8]
    emit(b'\x48\x8b\x82' + struct.pack('<I', RIP))            # mov rax,[rdx+Rip]
    emit(b'\x49\xb8' + struct.pack('<Q', data + 0x1B8))
    emit(b'\x49\x89\x00')                                     # [data+0x1B8]=rip
    # any exception whose RIP is inside our own page -> redirect
    emit(b'\x49\xb8' + struct.pack('<Q', code_lo))
    emit(b'\x4c\x39\xc0')
    rel8(b'\x72', 'not_ours')                                 # jb
    emit(b'\x49\xb8' + struct.pack('<Q', code_hi))
    emit(b'\x4c\x39\xc0')
    rel8(b'\x73', 'not_ours')                                 # jae
    rel8(b'\xeb', 'redirect')
    mark('not_ours')
    emit(b'\x3d' + struct.pack('<I', STATUS_SINGLE_STEP))
    rel8(b'\x75', 'pass')
    emit(b'\x49\xb8' + struct.pack('<Q', text_lo))
    emit(b'\x4c\x39\xc0')
    rel8(b'\x72', 'pass')
    emit(b'\x49\xb8' + struct.pack('<Q', text_hi))
    emit(b'\x4c\x39\xc0')
    rel8(b'\x73', 'pass')
    mark('redirect')
    emit(b'\x49\xb8' + struct.pack('<Q', data + 0x1C0))
    emit(b'\x41\xff\x00')                                     # inc redirects
    emit(b'\xc7\x82' + struct.pack('<I', EFLAGS) + struct.pack('<I', 0x202))
    emit(b'\x48\xb8' + struct.pack('<Q', safe_addr))
    emit(b'\x48\x89\x82' + struct.pack('<I', RIP))
    emit(b'\xb8\xff\xff\xff\xff')
    emit(b'\xc3')
    mark('pass')
    emit(b'\x31\xc0')
    emit(b'\xc3')
    for at, lab in fix:
        tgt = labels[lab]
        b[at] = (tgt - (at + 1)) & 0xff
    return bytes(b)


def build_register2(aveh, handler, slot):
    return (b'\x48\xb8' + struct.pack('<Q', aveh)
            + b'\x48\xc7\xc1\x01\x00\x00\x00'
            + b'\x48\xba' + struct.pack('<Q', handler)
            + b'\x48\x83\xec\x28'
            + b'\xff\xd0'
            + b'\x48\x83\xc4\x28'
            + b'\x49\xb8' + struct.pack('<Q', slot)
            + b'\x49\x89\x00'                                 # mov [r8],rax
            + b'\xb8\x7e\x7e\x7e\x7e'
            + b'\xc3')


def main():
    pid, h = fp.open_target(sys.argv[1])
    base, path = fp.main_module(h)
    t = fp.sections_of(fp.DISK)['.text']
    vsz, addr0 = t['vsz'], base + t['va']

    k32h = fp.k32.GetModuleHandleW('kernel32')
    aveh = fp.k32.GetProcAddress(k32h, b'AddVectoredExceptionHandler')

    code = fp.k32.VirtualAllocEx(h, None, 0x1000, 0x3000, 0x40)
    data = code + 0x400
    wr(h, data, b'\x00' * 0x40)
    handler = build_handler3(code, code + 0x1000, addr0, addr0 + vsz, code + 0x100, data)
    wr(h, code, handler)
    wr(h, code + 0x100, build_safe())
    wr(h, code + 0x300, build_register2(aveh, code, data + HANDLE_SLOT))
    print(f'pid {pid}  code {code:#x}  handler {len(handler)} bytes')
    print(f'handler: {handler.hex()}\n')

    ec, n, err = run_once(h, code + 0x300, tries=200, wait_ms=100)
    print(f'register stub: exit {"None" if ec is None else hex(ec)} after {n} attempts {err}')
    if ec != 0x7E7E7E7E:
        return 2
    hval = struct.unpack_from('<Q', rd(h, data + HANDLE_SLOT, 8) or b'\0' * 8, 0)[0]
    print(f'AddVectoredExceptionHandler returned {hval:#x}  '
          f'{"REGISTERED" if hval else "FAILED"}')
    if not hval:
        print('the packer (or a hook) is refusing VEH registration')
        return 3

    print('\nint3 stub (STATUS_BREAKPOINT)')
    wr(h, code + 0x200, b'\xcc\x31\xc0\xc3')
    ec, n, err = run_once(h, code + 0x200, tries=200, wait_ms=100)
    print(f'  exit {"None" if ec is None else hex(ec)} after {n} attempts {err}')
    red = struct.unpack_from('<I', rd(h, data + 0x1C0, 4) or b'\0' * 4, 0)[0]
    lastrip = struct.unpack_from('<Q', rd(h, data + 0x1B8, 8) or b'\0' * 8, 0)[0]
    lastcode = struct.unpack_from('<I', rd(h, data + 0x1B0, 4) or b'\0' * 4, 0)[0]
    print(f'  redirects={red}  last exception rip={lastrip:#x} code={lastcode:#x}')
    print(f'  verdict: {"HANDLER REACHABLE" if ec == 0x5A5A else "handler did not run"}')
    print(f'  process alive: {fp.alive(h)}')
    if not fp.alive(h):
        return 4

    print('\nAV stub (write to 0x10)')
    wr(h, code + 0x200, b'\x48\xc7\xc0\x10\x00\x00\x00\xc7\x00\x01\x00\x00\x00\x31\xc0\xc3')
    ec, n, err = run_once(h, code + 0x200, tries=200, wait_ms=100)
    print(f'  exit {"None" if ec is None else hex(ec)} after {n} attempts {err}')
    print(f'  process alive: {fp.alive(h)}')
    if not fp.alive(h):
        print('  the AV was NOT redirected: for access violations the packer is')
        print('  ahead of our handler (or the exception never reached the chain)')
        return 5
    print(f'  verdict: {"AV REDIRECTED" if ec == 0x5A5A else "AV swallowed elsewhere"}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

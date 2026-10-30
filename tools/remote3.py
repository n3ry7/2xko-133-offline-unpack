"""remote3.py - CreateRemoteThread with a stub that depends on no register.

Earlier stubs did `mov [rcx], 0xDEADBEEF` on the assumption that RCX holds the
thread parameter. On x64 a thread start routine receives its parameter in RCX
*when entered via BaseThreadInitThunk*, but the target of CreateRemoteThread is
called by RtlUserThreadStart, which does `call rcx` - so inside the stub RCX is
still the start routine's own address, and the parameter is in RDX. Every
earlier "no marker" result wrote into the stub's own code page instead.

This version bakes the destination addresses into the stub as imm64s, so no
register convention can be wrong. Thread exits by returning into
RtlUserThreadStart, which then exits the thread with code 0.

  A  marker only                     -> does remote code run at all?
  B  read one byte of a NOACCESS page -> does a READ fault decrypt .text?

    python remote3.py <pid|exe> [--page RVA]
"""
import ctypes
import ctypes.wintypes as w
import struct
import sys
import time

sys.path.insert(0, r'C:\2XKO-unpack')
import faultprobe as fp

PAGE = 0x1000

# param layout (0x1000 page, caller-owned):
#   +0x10 marker_enter   0x11111111 written before the faulting read
#   +0x14 marker_after   0x22222222 written after the read returned
#   +0x18 byte_read      the byte the read produced
MARK_ENTER = 0x11111111
MARK_AFTER = 0x22222222


def mov_rax(imm):
    return b'\x48\xb8' + struct.pack('<Q', imm)


def mov_rbx(imm):
    return b'\x48\xbb' + struct.pack('<Q', imm)


def mov_rcx(imm):
    return b'\x48\xb9' + struct.pack('<Q', imm)


def stub_mark(param):
    return (mov_rax(param)
            + b'\xc7\x00\xef\xbe\xad\xde'      # mov dword [rax],0xDEADBEEF
            + b'\x31\xc0\xc3')                 # xor eax,eax; ret


def stub_read(param, page):
    return (mov_rax(param)
            + b'\xc7\x00' + struct.pack('<I', MARK_ENTER)   # [param+0x00] = enter
            + mov_rbx(page)
            + b'\x8a\x03'                                    # mov al,[rbx]  <-- fault
            + mov_rcx(param)
            + b'\xc7\x41\x04' + struct.pack('<I', MARK_AFTER)  # [param+4] = after
            + b'\x0f\xb6\xc0'                                # movzx eax,al
            + b'\x89\x41\x08'                                # [param+8] = byte read
            + b'\x31\xc0\xc3')                               # xor eax,eax; ret


def wr(h, addr, data):
    got = ctypes.c_size_t(0)
    ok = fp.k32.WriteProcessMemory(h, ctypes.c_void_p(addr), data, len(data),
                                   ctypes.byref(got))
    return bool(ok) and got.value == len(data)


def rd(h, addr, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if not fp.k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)):
        return None
    return buf.raw[:got.value]


def run(h, code, param, label, timeout=5.0):
    tid = w.DWORD(0)
    th = fp.k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(code),
                                   ctypes.c_void_p(param), 0, ctypes.byref(tid))
    if not th:
        print(f'   {label}: CreateRemoteThread FAILED err {ctypes.get_last_error()}')
        return None
    waited = fp.k32.WaitForSingleObject(th, int(timeout * 1000))
    ec = w.DWORD(0)
    fp.k32.GetExitCodeThread(th, ctypes.byref(ec))
    fp.k32.CloseHandle(th)
    note = 'finished' if waited == 0 else f'still running after {timeout}s'
    print(f'   {label}: tid {tid.value}  {note}  exit {ec.value}')
    return ec.value


def count_noaccess(h, addr0, npages):
    n = 0
    for o in range(npages):
        p = fp.prot_at(h, addr0 + o * PAGE)
        if p and (p[0] & 0xff) == fp.PAGE_NOACCESS:
            n += 1
    return n


def main():
    pid, h = fp.open_target(sys.argv[1])
    base, path = fp.main_module(h)
    t = fp.sections_of(fp.DISK)['.text']
    addr0 = base + t['va']
    npages = (t['vsz'] + PAGE - 1) // PAGE

    page_rva = None
    for i, a in enumerate(sys.argv):
        if a == '--page':
            page_rva = int(sys.argv[i + 1], 0)

    code = fp.k32.VirtualAllocEx(h, None, 0x1000, 0x3000, 0x40)
    param = fp.k32.VirtualAllocEx(h, None, 0x1000, 0x3000, 0x04)
    print(f'pid {pid}  base {base:#x}  .text va {t["va"]:#x} size {t["vsz"]:#x}')
    print(f'code {code:#x}  param {param:#x}')

    # ---- A: does remote code run at all? ---------------------------------
    print('\nA. marker stub, destination hardcoded')
    wr(h, code, stub_mark(param))
    wr(h, param, b'\x00' * 0x40)
    run(h, code, param, 'marker stub')
    blob = rd(h, param, 4)
    ok_a = blob == bytes.fromhex('efbeadde')
    print(f'   [param+0] = {"None" if blob is None else blob.hex()}  '
          f'{"MARKER PRESENT - remote code executes" if ok_a else "no marker"}')
    if not ok_a:
        print('\nSTOP: remote threads still do not execute our code.')
        return 1

    # ---- B: does a READ fault decrypt .text? -----------------------------
    if page_rva is None:
        # the packer installs its page protections during startup, so wait for
        # the first NOACCESS page instead of assuming a fixed delay
        deadline = time.time() + 240
        n_na = 0
        while time.time() < deadline:
            n_na = count_noaccess(h, addr0, npages)
            print(f'   NOACCESS pages right now: {n_na}', flush=True)
            if n_na:
                break
            if not fp.alive(h):
                print('\nprocess died while waiting for the packer')
                return 2
            time.sleep(5)
        if not n_na:
            print('\nno NOACCESS pages after 240 s - packer never installed its map')
            return 2
        best = (0, 0)
        rs, rl = None, 0
        for o in range(npages):
            p = fp.prot_at(h, addr0 + o * PAGE)
            if p and (p[0] & 0xff) == fp.PAGE_NOACCESS:
                if rs is None:
                    rs, rl = o, 0
                rl += PAGE
            else:
                if rs is not None and rl > best[0]:
                    best = (rl, rs)
                rs = None
        if rs is not None and rl > best[0]:
            best = (rl, rs)
        if not best[0]:
            print('\nno NOACCESS pages found - is the packer still running?')
            return 2
        off = best[1] + (best[0] // 2 // PAGE) * PAGE
        print(f'\nbiggest NOACCESS run: rva {t["va"] + best[1]:#x} + {best[0] / 1048576:.2f} MB')
    else:
        off = page_rva - t['va']
    page = addr0 + off
    print(f'B. read one byte at rva {t["va"] + off:#x}  va {page:#x}')
    print(f'   protection before: {fp.prot_name(fp.prot_at(h, page)[0])}  '
          f'readable={fp.readable(h, page)}')

    wr(h, code, stub_read(param, page))
    wr(h, param, b'\x00' * 0x40)
    code_bytes = rd(h, code, 48)
    print(f'   stub bytes: {code_bytes.hex() if code_bytes else None}')
    run(h, code, param, 'read stub')

    raw = rd(h, param, 12) or b'\0' * 12
    m1, m2, val = struct.unpack_from('<III', raw, 0)
    print(f'   marker_enter {m1:#010x}  (0x11111111 = stub started)')
    print(f'   marker_after {m2:#010x}  (0x22222222 = read returned)')
    print(f'   byte read    {val:#04x}')
    p = fp.prot_at(h, page)
    print(f'   protection after:  {fp.prot_name(p[0]) if p else "NO-PROCESS"}  '
          f'readable={fp.readable(h, page)}')
    print(f'   process alive: {fp.alive(h)}')

    print('\n--- verdict ---')
    if m2 == MARK_AFTER and p and (p[0] & 0xff) == fp.PAGE_NOACCESS:
        print('The read returned and the page stayed NOACCESS: a read does NOT')
        print('decrypt. The handler resolved the fault without touching the page.')
    elif m2 == MARK_AFTER:
        print(f'The read returned and protection became {fp.prot_name(p[0])} - the')
        print('handler decrypted the page. Reads ARE a decryption path.')
    elif m1 == MARK_ENTER:
        print('The stub started but never came back from the read: the fault did')
        print('not resolve, or the thread was killed inside it.')
    else:
        print('The read stub did not start even though the marker stub did.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

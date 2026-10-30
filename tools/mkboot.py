"""mkboot.py - build the bootstrap section that fills the packer's IAT.

The packer's original IAT cannot be declared through import descriptors (blocks are
separated by a sentinel instead of a null, and the slots resolve to forwarders), so a
stub fills all 1,214 slots by name at load time and then jumps to the real OEP.

Windows ignores the import directory we synthesise for this image - verified: a bogus
DLL name does not even fail CreateProcess and the thunks stay zero - so the stub does
not rely on the loader at all. It resolves its own kernel32 entry points:

  1. PEB -> Ldr -> InLoadOrderModuleList, first module whose export name is "KERNEL32"
  2. parse that export table for LoadLibraryA and GetProcAddress (both are real code,
     not forwarders, on Windows and on Wine's kernel32)
  3. for each import: LoadLibraryA(module), GetProcAddress(handle, name) -> slot
  4. jmp OEP

Layout of the section (offsets from its start):
  0x000  code                        (must end before 0x740)
  0x740  resolved LoadLibraryA
  0x748  resolved GetProcAddress
  0x750  marker byte (image base = its address - its offset)
  0x760  module handle cache (u64 per module, room for 64)
  0x960  module name RVA table (u32 per module, room for 64)
  0xa80  entries (slot_rva u32, module index u32, name_rva u32, pad u32)
  ...    pool: module name strings, then import name strings

Build with `build(imports, oep_rva, section_rva)`; returns (bytes, info).
"""
import struct

import capstone

CODE = 0x000
SLOT_LL = 0x740
SLOT_GPA = 0x748
MARKER = 0x750
HANDLES = 0x760
MODNAMES = 0x960
ENTRIES = 0xA80
CODE_MAX = SLOT_LL
MAX_MODULES = 64

KERNEL32_PREFIX = int.from_bytes(b'KERNEL32', 'little')
LL_PREFIX = int.from_bytes(b'LoadLibr', 'little')
LL_TAIL = int.from_bytes(b'aryA', 'little')
GPA_PREFIX = int.from_bytes(b'GetProcA', 'little')
GPA_MID = int.from_bytes(b'ddre', 'little')
GPA_TAIL = int.from_bytes(b'ss', 'little')


class Asm:
    """Tiny x64 emitter for the encodings this stub needs, with label fixups."""

    def __init__(self):
        self.b = bytearray()
        self.rel = []      # (disp_position, label)
        self.rip = []      # (disp_position, section_offset)

    def e(self, *xs):
        for x in xs:
            self.b.extend(x if isinstance(x, (bytes, bytearray)) else bytes(x))

    def jmp(self, op, label):
        """op: opcode bytes; emits a rel32 to `label`."""
        self.e(op)
        self.rel.append((len(self.b), label))
        self.e(b'\x00\x00\x00\x00')

    def ripref(self, op, target_off):
        """op: opcode bytes ending in the modrm for [rip+disp32]."""
        self.e(op)
        self.rip.append((len(self.b), target_off))
        self.e(b'\x00\x00\x00\x00')

    def imm32(self, op, value):
        self.e(op, struct.pack('<I', value))

    def resolve(self, labels):
        for pos, lab in self.rel:
            if lab not in labels:
                raise SystemExit(f'mkboot: unresolved label {lab}')
            struct.pack_into('<i', self.b, pos, labels[lab] - (pos + 4))
        for pos, off in self.rip:
            struct.pack_into('<i', self.b, pos, off - (pos + 4))


def emit(section_rva, oep_rva, n_imports):
    a = Asm()
    lab = {}

    def L(name):
        lab[name] = len(a.b)

    # ---- prologue --------------------------------------------------------
    a.e(b'\x53', b'\x55', b'\x56', b'\x57')                       # push rbx,rbp,rsi,rdi
    a.e(b'\x41\x54', b'\x41\x55', b'\x41\x56', b'\x41\x57')       # push r12..r15
    a.e(b'\x48\x83\xec\x28')                                      # sub rsp,0x28

    # ---- image base ------------------------------------------------------
    a.ripref(b'\x4c\x8d\x3d', MARKER)                             # lea r15,[rip+marker]
    a.imm32(b'\x49\x81\xef', section_rva + MARKER)                # sub r15,imm32

    # ---- find kernel32 by export name ------------------------------------
    a.e(b'\x65\x48\x8b\x04\x25\x60\x00\x00\x00')   # mov rax,gs:[0x60]      PEB
    a.e(b'\x48\x8b\x40\x18')                        # mov rax,[rax+0x18]    Ldr
    a.e(b'\x48\x8b\x40\x10')                        # mov rax,[rax+0x10]    InLoadOrderModuleList
    a.e(b'\x48\x89\xc3')                            # mov rbx,rax
    a.e(b'\xbe\x10\x00\x00\x00')                    # mov esi,16
    L('walk')
    a.e(b'\x48\x8b\x43\x30')                        # mov rax,[rbx+0x30]    DllBase
    a.e(b'\x48\x85\xc0')                            # test rax,rax
    a.jmp(b'\x0f\x84', 'next')
    a.e(b'\x66\x81\x38\x4d\x5a')                    # cmp word [rax],'MZ'
    a.jmp(b'\x0f\x85', 'next')
    a.e(b'\x8b\x50\x3c')                            # mov edx,[rax+0x3c]    e_lfanew
    a.e(b'\x81\x3c\x10\x50\x45\x00\x00')            # cmp dword [rax+rdx],'PE\0\0'
    a.jmp(b'\x0f\x85', 'next')
    a.e(b'\x8b\x8c\x10\x88\x00\x00\x00')            # mov ecx,[rax+rdx+0x88]  export dir rva
    a.e(b'\x85\xc9')                                # test ecx,ecx
    a.jmp(b'\x0f\x84', 'next')
    a.e(b'\x49\x89\xc2')                            # mov r10,rax           candidate base
    a.e(b'\x48\x01\xc1')                            # add rcx,rax
    a.e(b'\x44\x8b\x59\x0c')                        # mov r11d,[rcx+0x0c]   export Name rva
    a.e(b'\x49\x01\xc3')                            # add r11,rax
    a.e(b'\x49\x8b\x13')                            # mov rdx,[r11]
    a.e(b'\x48\xb8', struct.pack('<Q', KERNEL32_PREFIX))
    a.e(b'\x48\x39\xc2')                            # cmp rdx,rax
    a.jmp(b'\x0f\x84', 'found')
    L('next')
    a.e(b'\x48\x8b\x1b')                            # mov rbx,[rbx]
    a.e(b'\xff\xce')                                # dec esi
    a.jmp(b'\x0f\x85', 'walk')
    a.jmp(b'\xe9', 'fail')

    # ---- kernel32 export table -------------------------------------------
    L('found')
    a.e(b'\x4c\x89\xd5')                            # mov rbp,r10
    a.e(b'\x8b\x45\x3c')                            # mov eax,[rbp+0x3c]
    a.e(b'\x8b\xbc\x05\x88\x00\x00\x00')            # mov edi,[rbp+rax+0x88]
    a.e(b'\x48\x01\xef')                            # add rdi,rbp            export dir
    a.e(b'\x44\x8b\x77\x18')                        # mov r14d,[rdi+0x18]    NumberOfNames
    a.e(b'\x8b\x77\x20')                            # mov esi,[rdi+0x20]
    a.e(b'\x48\x01\xee')                            # add rsi,rbp            AddressOfNames
    a.e(b'\x44\x8b\x67\x24')                        # mov r12d,[rdi+0x24]
    a.e(b'\x49\x01\xec')                            # add r12,rbp            AddressOfNameOrdinals
    a.e(b'\x44\x8b\x6f\x1c')                        # mov r13d,[rdi+0x1c]
    a.e(b'\x49\x01\xed')                            # add r13,rbp            AddressOfFunctions

    # ---- LoadLibraryA ----------------------------------------------------
    a.e(b'\x31\xdb')                                # xor ebx,ebx
    L('ll_loop')
    a.e(b'\x44\x39\xf3')                            # cmp ebx,r14d
    a.jmp(b'\x0f\x83', 'fail')
    a.e(b'\x44\x8b\x1c\x9e')                        # mov r11d,[rsi+rbx*4]
    a.e(b'\x49\x01\xeb')                            # add r11,rbp
    a.e(b'\x49\x8b\x03')                            # mov rax,[r11]
    a.e(b'\x49\xba', struct.pack('<Q', LL_PREFIX))
    a.e(b'\x4c\x39\xd0')                            # cmp rax,r10
    a.jmp(b'\x0f\x85', 'll_next')
    a.e(b'\x41\x81\x7b\x08', struct.pack('<I', LL_TAIL))    # cmp dword [r11+8],'aryA'
    a.jmp(b'\x0f\x85', 'll_next')
    a.e(b'\x41\x0f\xb7\x04\x5c')                    # movzx eax,word [r12+rbx*2]
    a.e(b'\x45\x8b\x54\x85\x00')                    # mov r10d,[r13+rax*4+0]
    a.e(b'\x49\x01\xea')                            # add r10,rbp
    a.e(b'\x4d\x89\x97', struct.pack('<I', section_rva + SLOT_LL))   # mov [r15+SLOT_LL],r10
    a.jmp(b'\xe9', 'gpa')
    L('ll_next')
    a.e(b'\xff\xc3')                                # inc ebx
    a.jmp(b'\x0f\x85', 'll_loop')
    a.jmp(b'\xe9', 'fail')

    # ---- GetProcAddress --------------------------------------------------
    L('gpa')
    a.e(b'\x31\xdb')                                # xor ebx,ebx
    L('gpa_loop')
    a.e(b'\x44\x39\xf3')                            # cmp ebx,r14d
    a.jmp(b'\x0f\x83', 'fail')
    a.e(b'\x44\x8b\x1c\x9e')                        # mov r11d,[rsi+rbx*4]
    a.e(b'\x49\x01\xeb')                            # add r11,rbp
    a.e(b'\x49\x8b\x03')                            # mov rax,[r11]
    a.e(b'\x49\xba', struct.pack('<Q', GPA_PREFIX))
    a.e(b'\x4c\x39\xd0')                            # cmp rax,r10
    a.jmp(b'\x0f\x85', 'gpa_next')
    a.e(b'\x41\x81\x7b\x08', struct.pack('<I', GPA_MID))    # cmp dword [r11+8],'ddre'
    a.jmp(b'\x0f\x85', 'gpa_next')
    a.e(b'\x66\x41\x81\x7b\x0c', struct.pack('<H', GPA_TAIL))  # cmp word [r11+0xc],'ss'
    a.jmp(b'\x0f\x85', 'gpa_next')
    a.e(b'\x41\x0f\xb7\x04\x5c')                    # movzx eax,word [r12+rbx*2]
    a.e(b'\x45\x8b\x54\x85\x00')                    # mov r10d,[r13+rax*4+0]
    a.e(b'\x49\x01\xea')                            # add r10,rbp
    a.e(b'\x4d\x89\x97', struct.pack('<I', section_rva + SLOT_GPA))  # mov [r15+SLOT_GPA],r10
    a.jmp(b'\xe9', 'fill')
    L('gpa_next')
    a.e(b'\xff\xc3')                                # inc ebx
    a.jmp(b'\x0f\x85', 'gpa_loop')
    a.jmp(b'\xe9', 'fail')

    # ---- fill the packer IAT ---------------------------------------------
    L('fill')
    a.ripref(b'\x48\x8d\x35', ENTRIES)              # lea rsi,[rip+entries]
    a.imm32(b'\xbf', n_imports)                     # mov edi,count
    L('loop')
    a.e(b'\x8b\x46\x04')                            # mov eax,[rsi+4]      module index
    a.ripref(b'\x48\x8d\x15', HANDLES)              # lea rdx,[rip+handles]
    a.e(b'\x48\x8b\x0c\xc2')                        # mov rcx,[rdx+rax*8]
    a.e(b'\x48\x85\xc9')                            # test rcx,rcx
    a.jmp(b'\x0f\x85', 'have')
    a.ripref(b'\x48\x8d\x15', MODNAMES)             # lea rdx,[rip+modnames]
    a.e(b'\x8b\x0c\x82')                            # mov ecx,[rdx+rax*4]
    a.e(b'\x4c\x01\xf9')                            # add rcx,r15
    a.e(b'\x49\x8b\x87', struct.pack('<I', section_rva + SLOT_LL))   # mov rax,[r15+SLOT_LL]
    a.e(b'\xff\xd0')                                # call rax
    a.e(b'\x44\x8b\x4e\x04')                        # mov r9d,[rsi+4]
    a.ripref(b'\x48\x8d\x15', HANDLES)              # lea rdx,[rip+handles]
    a.e(b'\x4a\x89\x04\xca')                        # mov [rdx+r9*8],rax
    a.e(b'\x48\x89\xc1')                            # mov rcx,rax
    L('have')
    a.e(b'\x8b\x56\x08')                            # mov edx,[rsi+8]      name rva
    a.e(b'\x4c\x01\xfa')                            # add rdx,r15
    a.e(b'\x49\x8b\x87', struct.pack('<I', section_rva + SLOT_GPA))  # mov rax,[r15+SLOT_GPA]
    a.e(b'\xff\xd0')                                # call rax
    a.e(b'\x8b\x1e')                                # mov ebx,[rsi]        slot rva
    a.e(b'\x4c\x01\xfb')                            # add rbx,r15
    a.e(b'\x48\x89\x03')                            # mov [rbx],rax
    a.e(b'\x48\x83\xc6\x10')                        # add rsi,16
    a.e(b'\x83\xef\x01')                            # sub edi,1
    a.jmp(b'\x0f\x85', 'loop')

    # ---- hand over to the real entry point -------------------------------
    a.imm32(b'\x49\x8d\x87', oep_rva)               # lea rax,[r15+oep]
    a.e(b'\x48\x83\xc4\x28')                        # add rsp,0x28
    a.e(b'\x41\x5f', b'\x41\x5e', b'\x41\x5d', b'\x41\x5c')
    a.e(b'\x5f', b'\x5e', b'\x5d', b'\x5b')
    a.e(b'\xff\xe0')                                # jmp rax

    L('fail')
    a.e(b'\x0f\x0b')                                # ud2

    a.resolve(lab)
    return bytes(a.b)


def build(imports, oep_rva, section_rva):
    modules = sorted({i['module'] for i in imports})
    if len(modules) > MAX_MODULES:
        raise SystemExit(f'mkboot: {len(modules)} modules exceed {MAX_MODULES}')
    mod_index = {m: k for k, m in enumerate(modules)}
    n = len(imports)

    pool_base_off = ENTRIES + n * 16
    pool = bytearray()

    def add(s):
        off = pool_base_off + len(pool)
        pool.extend(s.encode('ascii') + b'\x00')
        return off

    mod_offs = {m: add(m) for m in modules}
    name_offs = {}
    for i in imports:
        key = (i['module'], i['name'])
        if key not in name_offs:
            name_offs[key] = add(i['name'])

    code = emit(section_rva, oep_rva, n)
    if len(code) > CODE_MAX:
        raise SystemExit(f'mkboot: code {len(code):#x} exceeds {CODE_MAX:#x}')

    total = pool_base_off + len(pool)
    buf = bytearray((total + 0xFFF) & ~0xFFF)
    buf[CODE:CODE + len(code)] = code

    for k, m in enumerate(modules):
        struct.pack_into('<I', buf, MODNAMES + k * 4, section_rva + mod_offs[m])

    for k, i in enumerate(imports):
        struct.pack_into('<IIII', buf, ENTRIES + k * 16, i['slot'],
                         mod_index[i['module']],
                         section_rva + name_offs[(i['module'], i['name'])], 0)

    buf[pool_base_off:pool_base_off + len(pool)] = pool

    return bytes(buf), {
        'n_imports': n,
        'n_modules': len(modules),
        'desc_rva': 0,
        'desc_size': 0,
        'code_size': len(code),
        'section_size': len(buf),
        'oep': oep_rva,
    }


def disasm(blob, base_rva=0, start=0, size=None):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    end = len(blob) if size is None else start + size
    for ins in md.disasm(bytes(blob[start:end]), base_rva + start):
        yield ins


if __name__ == '__main__':
    import json
    imp = json.load(open(r'C:\2XKO-unpack\dumpimg\imports.json'))
    sec, info = build(imp, 0x7E698B0, 0xBEF8000)
    print(info)
    seen = 0
    for ins in disasm(sec, 0xBEF8000, 0, info['code_size']):
        print(f'  {ins.address:#010x}  {ins.bytes.hex():<22} {ins.mnemonic:<8} {ins.op_str}')
        seen += 1
    print('instructions:', seen, 'code bytes:', info['code_size'])

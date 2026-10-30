"""dis.py - disassemble a range of stub.dll (or any PE) with IAT annotation.

    python dis.py <pe> <rva> [count] [--imports]

--imports   list the import table instead of disassembling

RIP-relative operands that point into the IAT are printed with the imported
function name, which is what makes obfuscated packer code readable.
"""
import struct
import sys

import capstone

PE = r'C:\Riot Games\2XKO_modded\Live\Lion\Binaries\Win64\stub.dll'


def u16(b, o): return struct.unpack_from('<H', b, o)[0]
def u32(b, o): return struct.unpack_from('<I', b, o)[0]


class PEfile:
    def __init__(self, path):
        self.path = path
        self.d = open(path, 'rb').read()
        d = self.d
        pe = u32(d, 0x3c)
        self.pe = pe
        self.image_base = struct.unpack_from('<Q', d, pe + 24 + 24)[0]
        nsec = u16(d, pe + 6)
        optsz = u16(d, pe + 20)
        so = pe + 24 + optsz
        self.sections = []
        for i in range(nsec):
            o = so + i * 40
            self.sections.append({
                'name': d[o:o + 8].rstrip(b'\0').decode('latin1'),
                'vsz': u32(d, o + 8), 'va': u32(d, o + 12),
                'rawsz': u32(d, o + 16), 'raw': u32(d, o + 20),
                'chars': u32(d, o + 36)})
        self.imp = {}
        self._parse_imports()

    def _parse_imports(self):
        d = self.d
        opt = self.pe + 24
        magic = u16(d, opt)
        if magic == 0x20b:
            dd = opt + 112
        else:
            dd = opt + 96
        imp_rva, imp_sz = u32(d, dd + 8), u32(d, dd + 12)
        if not imp_rva:
            return
        o = self.rva_to_off(imp_rva)
        i = 0
        while True:
            desc = o + i * 20
            oft, _ts, _fwd, name_rva, ft = (u32(d, desc), u32(d, desc + 4),
                                            u32(d, desc + 8), u32(d, desc + 12),
                                            u32(d, desc + 16))
            if not name_rva:
                break
            dll = self.cstr(name_rva)
            thunk_rva = oft or ft
            to = self.rva_to_off(thunk_rva)
            j = 0
            while True:
                v = struct.unpack_from('<Q', d, to + j * 8)[0]
                if v == 0:
                    break
                if v & 0x8000000000000000:
                    name = f'#{v & 0xffff}'
                else:
                    name = self.cstr((v & 0x7fffffff) + 2)
                self.imp[ft + j * 8] = (dll, name)
                j += 1
            i += 1

    def cstr(self, rva):
        o = self.rva_to_off(rva)
        e = self.d.index(b'\0', o)
        return self.d[o:e].decode('latin1')

    def rva_to_off(self, rva):
        for s in self.sections:
            if s['va'] <= rva < s['va'] + max(s['vsz'], s['rawsz']):
                return s['raw'] + (rva - s['va'])
        raise ValueError(f'rva {rva:#x} not in any section')

    def read(self, rva, n):
        o = self.rva_to_off(rva)
        return self.d[o:o + n]


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else PE
    p = PEfile(path)

    if '--imports' in sys.argv or len(sys.argv) < 3:
        print(f'{path}  ({len(p.d):,} bytes)  image base {p.image_base:#x}')
        print(f'imports: {len(p.imp)} functions from '
              f'{len(set(v[0] for v in p.imp.values()))} DLLs\n')
        for slot in sorted(p.imp):
            dll, fn = p.imp[slot]
            print(f'  IAT {slot:#08x}  {dll:<14} {fn}')
        return 0

    rva = int(sys.argv[2], 0)
    count = int(sys.argv[3]) if len(sys.argv) > 3 and not sys.argv[3].startswith('-') else 120
    sec = next((s for s in p.sections if s['va'] <= rva < s['va'] + s['vsz']), None)
    print(f'{path}:{rva:#x}  section {sec["name"] if sec else "?"}  '
          f'({count} instructions)\n')

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    off_rva = rva
    code = p.read(rva, min(count * 16, 0x10000))
    n = 0
    for ins in md.disasm(code, p.image_base + rva):
        cur = ins.address - p.image_base
        note = ''
        if ins.mnemonic == 'call' or ins.mnemonic == 'jmp':
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    tgt = cur + ins.size + op.mem.disp
                    if tgt in p.imp:
                        dll, fn = p.imp[tgt]
                        note = f'   ; -> {dll}!{fn}'
                    else:
                        note = f'   ; IAT {tgt:#x}'
        print(f'{cur:08x}  {ins.bytes.hex():<24} {ins.mnemonic:<8} {ins.op_str}{note}')
        n += 1
        if n >= count:
            break
    return 0


if __name__ == '__main__':
    sys.exit(main())

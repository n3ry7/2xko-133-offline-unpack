"""rebuild2.py - produce an unpacked, bootstrapped exe.

Steps:
  * write the decrypted .text over the encrypted bytes
  * mark .text executable (0x60000020)
  * point the entry point at a new .boot section
  * .boot fills the packer's original IAT slots by name (LoadLibraryA +
    GetProcAddress), then jumps to the real OEP
  * the import directory declares exactly KERNEL32!LoadLibraryA and
    KERNEL32!GetProcAddress, whose thunks live in .boot

    python rebuild2.py --out unpacked.exe [--text textdump/text.bin]
"""
import argparse
import json
import os
import struct
import sys

sys.path.insert(0, r'C:\2XKO-unpack')
import faultprobe as fp
import mkboot
from pe_dis import PEfile

OEP = 0x7E698B0
SECT_CHARS = 0x60000020
BOOT_CHARS = 0xE0000020   # code|execute|read|write: the bootstrap stores handles
FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--text', default=r'C:\2XKO-unpack\textdump\text.bin')
    ap.add_argument('--imports', default=r'C:\2XKO-unpack\dumpimg\imports.json')
    a = ap.parse_args()

    data = bytearray(open(fp.DISK, 'rb').read())
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    opt = pe + 24
    nsec = struct.unpack_from('<H', data, pe + 6)[0]
    so = opt + struct.unpack_from('<H', data, pe + 20)[0]
    magic = struct.unpack_from('<H', data, opt)[0]
    dd = opt + (112 if magic == 0x20b else 96)

    secs = []
    for i in range(nsec):
        o = so + i * 40
        name = data[o:o + 8].rstrip(b'\0').decode('latin-1')
        vsz, va, rawsz, raw = struct.unpack_from('<IIII', data, o + 8)
        secs.append({'hdr': o, 'name': name, 'va': va, 'vsz': vsz,
                     'rawsz': rawsz, 'raw': raw})

    text = next(s for s in secs if s['name'] == '.text')
    body = open(a.text, 'rb').read()
    print(f'text.bin {len(body):,} bytes, .text vsz {text["vsz"]:,}')
    if len(body) != text['vsz']:
        raise SystemExit('text.bin size mismatch')
    data[text['raw']:text['raw'] + len(body)] = body

    struct.pack_into('<I', data, text['hdr'] + 36, SECT_CHARS)
    print(f'.text chars -> {SECT_CHARS:#x}')

    # the bootstrap writes the resolved addresses into the packer's IAT, which
    # lives at the start of .rdata; that section must be writable at load time
    rdata = next(s for s in secs if s['name'] == '.rdata')
    struct.pack_into('<I', data, rdata['hdr'] + 36, 0xC0000040)
    print('.rdata chars -> 0xc0000040 (writable, so the IAT can be filled)')

    # new section
    end_rva = max(s['va'] + s['vsz'] for s in secs)
    boot_rva = (end_rva + SECT_ALIGN - 1) & ~(SECT_ALIGN - 1)
    imports = json.load(open(a.imports))
    print(f'{len(imports)} imports for the bootstrap')
    sec, info = mkboot.build(imports, OEP, boot_rva)
    print(f'.boot rva {boot_rva:#x} size {len(sec):#x}  {info}')

    raw_off = (len(data) + FILE_ALIGN - 1) & ~(FILE_ALIGN - 1)
    pad = raw_off - len(data)
    data.extend(b'\x00' * pad)
    rawsz = (len(sec) + FILE_ALIGN - 1) & ~(FILE_ALIGN - 1)
    data.extend(sec)
    data.extend(b'\x00' * (rawsz - len(sec)))

    hdr = so + nsec * 40
    data[hdr:hdr + 8] = b'.boot\x00\x00\x00'
    struct.pack_into('<IIII', data, hdr + 8, len(sec), boot_rva, rawsz, raw_off)
    struct.pack_into('<II', data, hdr + 24, 0, 0)
    struct.pack_into('<HH', data, hdr + 32, 0, 0)
    struct.pack_into('<I', data, hdr + 36, BOOT_CHARS)

    struct.pack_into('<H', data, pe + 6, nsec + 1)
    size_of_image = (boot_rva + len(sec) + SECT_ALIGN - 1) & ~(SECT_ALIGN - 1)
    struct.pack_into('<I', data, opt + 56, size_of_image)
    struct.pack_into('<I', data, opt + 16, boot_rva)          # entry point
    struct.pack_into('<II', data, dd + 8, info['desc_rva'], info['desc_size'])
    print(f'entry -> {boot_rva:#x}   SizeOfImage -> {size_of_image:#x}')
    print(f'import dir -> rva {info["desc_rva"]:#x} size {info["desc_size"]:#x}')

    open(a.out, 'wb').write(data)
    print(f'wrote {a.out} ({len(data):,} bytes)')

    chk = PEfile(a.out)
    print('verify sections:', [(s['name'], hex(s['va']), hex(s['chars'])) for s in chk.sections])
    return 0


if __name__ == '__main__':
    sys.exit(main())

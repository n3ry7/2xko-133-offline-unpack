"""recover.py - rebuild textdump/dumped.bin from text.bin.

A decrypted page differs from the ciphertext on disk, so the bitmap can always be
reconstructed: for each page, compare text.bin against the corresponding bytes of
the original exe. Run this after a crash or a power loss if dumped.bin looks
wiped, then continue the walk from the reported page.

    python recover.py
"""
import sys

sys.path.insert(0, r'C:\2XKO-unpack')
import faultprobe as fp

PAGE = 0x1000
OUT = r'C:\2XKO-unpack\textdump'


def main():
    t = fp.sections_of(fp.DISK)['.text']
    disk = open(fp.DISK, 'rb').read()
    text = open(OUT + r'\text.bin', 'rb').read()
    vsz = t['vsz']
    npages = (vsz + PAGE - 1) // PAGE
    if len(text) != vsz:
        print(f'warning: text.bin is {len(text)} bytes, expected {vsz}')

    bitmap = bytearray(npages)
    for i in range(npages):
        off = i * PAGE
        n = min(PAGE, vsz - off)
        if text[off:off + n] != disk[t['raw'] + off:t['raw'] + off + n]:
            bitmap[i] = 1

    n = sum(bitmap)
    open(OUT + r'\dumped.bin', 'wb').write(bytes(bitmap))
    first = next((i for i in range(npages) if not bitmap[i]), npages)
    open(OUT + r'\next.txt', 'w').write(str(first))
    print(f'recovered {n} / {npages} pages ({100 * n / npages:.1f}%)')
    print(f'next undumped page: {first}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

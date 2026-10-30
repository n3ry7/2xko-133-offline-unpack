"""verify.py - compare readable pages of the live process against text.bin.

The dump read some pages too early (protection turns RX before the plaintext write
finishes), so a verification pass is needed. This checks every page that is already
readable right now - no faulting, no risk to the process - and reports mismatches.

    python verify.py <pid|exe> [--fix]
"""
import sys

sys.path.insert(0, r'C:\2XKO-unpack')
import faultprobe as fp

PAGE = 0x1000
TXT = r'C:\2XKO-unpack\textdump\text.bin'


def main():
    pid, h = fp.open_target(sys.argv[1])
    base, _ = fp.main_module(h)
    t = fp.sections_of(fp.DISK)['.text']
    addr0 = base + t['va']
    vsz = t['vsz']
    npages = (vsz + PAGE - 1) // PAGE
    dump = open(TXT, 'rb').read()
    fix = '--fix' in sys.argv

    checked = diff = 0
    bad = []
    for i in range(npages):
        addr = addr0 + i * PAGE
        if not fp.readable(h, addr, 4):
            continue
        n = min(PAGE, vsz - i * PAGE)
        live = fp.read_bytes(h, addr, n)
        if live is None or len(live) != n:
            continue
        checked += 1
        mine = dump[i * PAGE:i * PAGE + n]
        if live != mine:
            diff += 1
            if len(bad) < 20:
                # first differing offset
                k = next(j for j in range(n) if live[j] != mine[j])
                bad.append((i, k, t['va'] + i * PAGE))
    print(f'checked {checked} readable pages, {diff} differ')
    for i, k, rva in bad[:10]:
        print(f'  page {i} (rva {rva:#x}) first diff at +{k:#x}')

    if fix and diff:
        with open(TXT, 'r+b') as f:
            fixed = 0
            for i in range(npages):
                addr = addr0 + i * PAGE
                if not fp.readable(h, addr, 4):
                    continue
                n = min(PAGE, vsz - i * PAGE)
                live = fp.read_bytes(h, addr, n)
                if live is None or len(live) != n:
                    continue
                mine = dump[i * PAGE:i * PAGE + n]
                if live != mine:
                    f.seek(i * PAGE)
                    f.write(live)
                    fixed += 1
            print(f'fixed {fixed} pages in text.bin')
    return 0


if __name__ == '__main__':
    sys.exit(main())

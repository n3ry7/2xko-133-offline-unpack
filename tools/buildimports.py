"""buildimports.py - reconstruct an import table from the packer's resolved IAT.

The IAT at rva 0x8011000 is laid out normally: runs of resolved pointers grouped by
DLL, each run terminated by a null. We cannot trust the *owner* module to name the
DLL (kernel32 forwards to kernelbase), so each slot is resolved by address to
(owning module, export name) and the descriptors are grouped by that.

    python buildimports.py [--dir dumpimg]
"""
import os
import struct
import sys

sys.path.insert(0, r'C:\2XKO-unpack')
from pe_dis import PEfile

IAT_START = 0x8011000
MAX_SLOTS = 8192


def exports(path):
    """name -> rva, ordinal -> rva"""
    try:
        p = PEfile(path)
    except Exception:
        return {}, {}
    d = p.d
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    opt = pe + 24
    mag = struct.unpack_from('<H', d, opt)[0]
    dd = opt + (112 if mag == 0x20b else 96)
    exp_rva, exp_size = struct.unpack_from('<II', d, dd)
    if not exp_rva:
        return {}, {}

    def off(rva):
        for s in p.sections:
            if s['va'] <= rva < s['va'] + max(s['vsz'], s['rawsz']):
                return s['raw'] + rva - s['va']
        return None

    eo = off(exp_rva)
    if eo is None:
        return {}, {}
    try:
        base_ord, nfun, nnam = struct.unpack_from('<III', d, eo + 16)
        afun, anam, aord = struct.unpack_from('<III', d, eo + 28)
    except struct.error:
        return {}, {}
    by_name = {}
    by_ord = {}
    for i in range(nfun):
        frva = struct.unpack_from('<I', d, off(afun) + 4 * i)[0]
        by_ord[base_ord + i] = frva
    for i in range(nnam):
        nr = struct.unpack_from('<I', d, off(anam) + 4 * i)[0]
        o = off(nr)
        if o is None:
            continue
        e = d.index(b'\0', o)
        nm = d[o:e].decode('latin-1', 'replace')
        fi = struct.unpack_from('<H', d, off(aord) + 2 * i)[0]
        frva = struct.unpack_from('<I', d, off(afun) + 4 * fi)[0]
        if frva not in by_name:
            by_name[frva] = nm
    return by_name, by_ord


def main():
    d_dir = 'dumpimg'
    for i, a in enumerate(sys.argv):
        if a == '--dir':
            d_dir = sys.argv[i + 1]
    img = open(os.path.join(d_dir, 'image.bin'), 'rb').read()

    mods = []
    for line in open(os.path.join(d_dir, 'info.txt'), encoding='utf-8'):
        line = line.strip()
        if not line.startswith('0x'):
            continue
        b, p = line.split(' ', 1)
        if not os.path.exists(p):
            continue
        mods.append((int(b, 16), os.path.basename(p), p))
    mods.sort()

    exptabs = {}
    for base, name, path in mods:
        exptabs[name.lower()] = exports(path)
    print(f'{len(mods)} modules, export tables loaded')

    def owner(v):
        best = None
        for base, name, path in mods:
            if base <= v:
                best = (base, name)
            else:
                break
        return best

    slots = []
    off = IAT_START
    while off < len(img) and len(slots) < MAX_SLOTS:
        v = struct.unpack_from('<Q', img, off)[0]
        slots.append((off, v))
        off += 8
        # stop once we have gone well past the last import block
        if v == 0 and off > IAT_START + 0x4000:
            break

    # group: consecutive non-zero slots, terminated by zero
    groups = []
    cur = []
    for off, v in slots:
        if v == 0:
            if cur:
                groups.append(cur)
                cur = []
        else:
            cur.append((off, v))
    if cur:
        groups.append(cur)

    print(f'{len(groups)} import blocks')
    total = 0
    unresolved = 0
    for g in groups:
        names = {}
        for off, v in g:
            o = owner(v)
            if not o:
                unresolved += 1
                continue
            base, modname = o
            by_name, by_ord = exptabs.get(modname.lower(), ({}, {}))
            nm = by_name.get(v - base)
            key = modname
            names[key] = names.get(key, 0) + 1
            total += 1
        top = ', '.join(f'{k}:{n}' for k, n in sorted(names.items(), key=lambda kv: -kv[1])[:3])
        print(f'  {g[0][0]:#010x}..{g[-1][0] + 8:#010x}  {len(g):4d} slots  {top}')
    print(f'slots resolved {total}, unresolved {unresolved}')

    # emit the per-slot resolution for the bootstrap builder
    import json
    SENTINEL = 0xC01F9CEFB0F443AF
    out = []
    bad = []
    off = IAT_START
    while off < len(img):
        v = struct.unpack_from('<Q', img, off)[0]
        if v == SENTINEL:
            off += 8
            continue
        if v == 0 or v > 0x7FFFFFFFFFFF:
            break
        o = owner(v)
        if not o:
            bad.append((off, v))
            off += 8
            if len(bad) > 8:
                break
            continue
        base, modname = o
        by_name, by_ord = exptabs.get(modname.lower(), ({}, {}))
        nm = by_name.get(v - base)
        if nm is None:
            bad.append((off, v))
        else:
            out.append({'slot': off, 'module': modname, 'name': nm})
        off += 8
    json.dump(out, open(os.path.join(d_dir, 'imports.json'), 'w'), indent=0)
    print(f'wrote {len(out)} imports to {os.path.join(d_dir, "imports.json")}')
    mods_used = sorted(set(x['module'] for x in out))
    print(f'{len(mods_used)} modules: {mods_used[:8]}...')
    if bad:
        print(f'first unresolved slots: {[(hex(a), hex(v)) for a, v in bad[:5]]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

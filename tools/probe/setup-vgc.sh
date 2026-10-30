#!/usr/bin/env bash
# setup-vgc.sh - install vService.exe as the "vgc" service inside the Proton prefix.
#
# Keys in a Wine .reg file need doubled backslashes; the first attempt wrote single
# ones and Wine registered the service under a mangled key.
set -u
PFX="$HOME/2XKO/.prefix-133/pfx"
SRC="${1:-$HOME/2XKO/vService.exe}"
REG="$PFX/system.reg"

[ -f "$SRC" ] || { echo "missing $SRC"; exit 1; }
pkill -9 -f wineserver 2>/dev/null
pkill -9 -f wine 2>/dev/null
sleep 2

mkdir -p "$PFX/drive_c/vanguard"
cp "$SRC" "$PFX/drive_c/vanguard/vService.exe"
echo "binary: $(stat -c%s "$PFX/drive_c/vanguard/vService.exe") bytes"

python3 - "$REG" <<'PY'
import io
import re
import sys

path = sys.argv[1]
txt = io.open(path, encoding='latin-1').read()

# drop any previous (correct or mangled) attempt
txt = re.sub(r'\[System[^\r\n]*?Services\\\\?vgc\][^\r\n]*\r?\n(?:[^\[].*?\r?\n)*', '', txt)

key = '[System\\\\CurrentControlSet\\\\Services\\\\vgc]'
assert key == r'[System\\CurrentControlSet\\Services\\vgc]'
entry = (
    '\r\n' + key + ' 1699999999\r\n'
    '"DisplayName"="vgc"\r\n'
    '"ErrorControl"=dword:00000001\r\n'
    '"ImagePath"="C:\\\\vanguard\\\\vService.exe"\r\n'
    '"ObjectName"="LocalSystem"\r\n'
    '"Start"=dword:00000002\r\n'
    '"Type"=dword:00000010\r\n'
)
io.open(path, 'w', encoding='latin-1', newline='').write(txt + entry)
print('key written as:', key)
PY

echo "--- verify ---"
grep -n -A7 'Services\\\\vgc' "$REG" | head -n 9

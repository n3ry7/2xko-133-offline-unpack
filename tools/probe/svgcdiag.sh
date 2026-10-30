PFX="$HOME/2XKO/.prefix-133/pfx"
echo "--- key still in system.reg? ---"
grep -A6 'Services\\vgc' "$PFX/system.reg" | head -n 8
echo "--- wine output (service errors) ---"
grep -ai 'vgc\|service\|err:' /tmp/run133.out 2>/dev/null | head -n 12 | cut -c1-150
echo "--- wine log size ---"
wc -l /tmp/run133.out 2>/dev/null
echo "--- try starting the service with the prefix wine ---"
export WINEPREFIX="$HOME/2XKO/.prefix-133/pfx"
export WINEDLLOVERRIDES="ucrtbase=n,b"
W="$HOME/.steam/steam/steamapps/common/Proton - Experimental/files/bin/wine"
"$W" C:\\\\vanguard\\\\vService.exe 2>&1 | head -n 8
echo "--- reg query ---"
"$W" reg query 'HKLM\\System\\CurrentControlSet\\Services\\vgc' 2>&1 | head -n 12
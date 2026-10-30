#!/usr/bin/env bash
# vgctest.sh - launch with the vgc service registered and see if VAN-83 is gone.
set -u
L="$HOME/2XKO/.prefix-133/pfx/drive_c/users/steamuser/AppData/Local/Lion/Saved/Logs"
B="$L/Lion.log"
export WAYLAND_DISPLAY=wayland-1 XDG_RUNTIME_DIR=/run/user/1000 DISPLAY=:0

pkill -9 -f wine 2>/dev/null
pkill -9 -f wineserver 2>/dev/null
sleep 3
rm -f "$L"/Lion*.log /tmp/run133.out
: > /tmp/run133.out
( timeout 200 bash "$HOME/2XKO/run-133.sh" >>/tmp/run133.out 2>&1 ) &

for i in $(seq 1 170); do
    sleep 1
    grep -qa 'Mode.MainMenu' "$B" 2>/dev/null && { echo "MainMenu after ${i}s"; break; }
done
sleep 12

echo "--- vanguard ---"
grep -a 'LogLionVanguard\|VanguardFaulted\|RGIOPOfflineVanguard' "$B" 2>/dev/null | tail -n 6 | cut -c1-140
echo "--- modals ---"
grep -a 'Queued modal\|Showed modal' "$B" 2>/dev/null | tail -n 4 | cut -c1-130
echo "--- services / wine errors ---"
grep -ai 'service\|vgc' /tmp/run133.out 2>/dev/null | head -n 5 | cut -c1-140
echo "--- tail ---"
tail -n 3 "$B" | cut -c1-120
echo "--- vService running? ---"
pgrep -fa 'vService' | head -n 2 | cut -c1-100

#!/usr/bin/env bash
# matchtest.sh - launch, walk into a battle, watch the log and screenshot the result.
set -u
L="$HOME/2XKO/.prefix-133/pfx/drive_c/users/steamuser/AppData/Local/Lion/Saved/Logs"
B="$L/Lion.log"
export WAYLAND_DISPLAY=wayland-1 XDG_RUNTIME_DIR=/run/user/1000 DISPLAY=:0
KEY="$HOME/2XKO/key133.py"

killall -q -9 wine wine64 wineserver vService crashpad_handler EpicWebHelper Lion-Win64-Shipp
sleep 3
rm -f "$L"/Lion*.log /tmp/run133.out
: > /tmp/run133.out
( timeout 600 bash "$HOME/2XKO/run-133.sh" >>/tmp/run133.out 2>&1 ) &

for i in $(seq 1 160); do
    sleep 1
    grep -qa 'Mode.Game' "$B" 2>/dev/null && { echo "character select after ${i}s"; break; }
done
sleep 8
for n in 1 2 3 4 5 6; do
    python3 "$KEY" Return >/dev/null 2>&1
    sleep 4
done
echo "keys sent, watching..."

for i in $(seq 1 50); do
    sleep 5
    if grep -qa 'ELionMatchState\|Match Phase\|LogLionMatch\|MatchStart' "$B" 2>/dev/null; then
        echo "match marker at +$((i*5))s"
        break
    fi
done
sleep 5

echo "--- level spawner ---"
grep -a LogLionLevelSpawner "$B" 2>/dev/null | tail -n 4 | cut -c1-120
echo "--- match lines ---"
grep -ai -e matchstate -e matchphase -e matchstart -e LogLionMatch "$B" 2>/dev/null | tail -n 8 | cut -c1-120
echo "--- last 8 ---"
tail -n 8 "$B" 2>/dev/null | cut -c1-130
grim /tmp/match.png 2>/dev/null && echo "screenshot: $(stat -c%s /tmp/match.png) bytes"

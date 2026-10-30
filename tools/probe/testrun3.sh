#!/usr/bin/env bash
# testrun3.sh - launch via run-133.sh inside a live session, wait for MainMenu.
set -u
L="$HOME/2XKO/.prefix-133/pfx/drive_c/users/steamuser/AppData/Local/Lion/Saved/Logs"
B="$L/Lion.log"

pkill -9 -f wine 2>/dev/null
sleep 3
rm -f "$L"/Lion*.log /tmp/run133.out
: > /tmp/run133.out
( timeout 200 bash "$HOME/2XKO/run-133.sh" >>/tmp/run133.out 2>&1 ) &

for i in $(seq 1 170); do
    sleep 1
    if grep -qa 'Mode.MainMenu' "$B" 2>/dev/null; then
        echo "MainMenu reached after ${i}s"
        break
    fi
done
sleep 5

echo "--- timeline ---"
grep -aE 'FREGameModeState::(CheckDisconnectedSupport|RequireOnlinePlatform|AttractMode|Complete)|EnterMajorMode Mode.MainMenu|Showed modal' "$B" 2>/dev/null | cut -c1-120
echo "--- key presses ---"
grep -a 'key133' /tmp/run133.out 2>/dev/null | head -n 6
echo "--- launcher output tail ---"
tail -n 4 /tmp/run133.out 2>/dev/null | cut -c1-140
echo "--- game log tail ---"
tail -n 3 "$B" 2>/dev/null | cut -c1-130

pkill -9 -f wine 2>/dev/null

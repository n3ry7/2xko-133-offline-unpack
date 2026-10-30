#!/usr/bin/env bash
# shot133.sh - launch with the auto-confirm launcher, wait for the main menu,
# capture the screen if a screenshot tool exists.
set -u
L="$HOME/2XKO/.prefix-133/pfx/drive_c/users/steamuser/AppData/Local/Lion/Saved/Logs"
B="$L/Lion.log"
export WAYLAND_DISPLAY=wayland-1
export XDG_RUNTIME_DIR=/run/user/1000
export DISPLAY=:0

echo "tools: $(command -v grim) $(command -v scrot) $(command -v import) $(command -v ffmpeg)"

pkill -9 -f wine 2>/dev/null
sleep 3
rm -f "$L"/Lion*.log /tmp/run133.out
: > /tmp/run133.out
( timeout 180 bash "$HOME/2XKO/run-133.sh" >>/tmp/run133.out 2>&1 ) &

for i in $(seq 1 150); do
    sleep 1
    if grep -qa 'Mode.MainMenu' "$B" 2>/dev/null; then
        echo "MainMenu after ${i}s"
        break
    fi
done
sleep 8

if command -v grim >/dev/null 2>&1; then
    grim /tmp/menu133.png && echo "grim: $(stat -c%s /tmp/menu133.png) bytes"
elif command -v scrot >/dev/null 2>&1; then
    DISPLAY=:0 scrot -o /tmp/menu133.png && echo "scrot: $(stat -c%s /tmp/menu133.png) bytes"
elif command -v import >/dev/null 2>&1; then
    DISPLAY=:0 import -window root /tmp/menu133.png && echo "import: $(stat -c%s /tmp/menu133.png) bytes"
else
    echo "no screenshot tool"
fi

echo "--- state ---"
grep -aE 'FREGameModeState::(CheckDisconnectedSupport|RequireOnlinePlatform|Complete)|EnterMajorMode Mode.MainMenu|Showed modal' "$B" | cut -c1-115
echo "--- game log tail ---"
tail -n 3 "$B" | cut -c1-125
echo "--- game alive: $(pgrep -c -f Lion-Win64-Shipping || echo 0) ---"

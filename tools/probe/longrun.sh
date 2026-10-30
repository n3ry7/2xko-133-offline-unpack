#!/usr/bin/env bash
set -u
export XDG_RUNTIME_DIR=/run/user/1000
export DISPLAY=:0
export WAYLAND_DISPLAY=wayland-1
export STEAM_COMPAT_DATA_PATH="$HOME/2XKO/.prefix-133"
export STEAM_COMPAT_CLIENT_INSTALL_PATH="$HOME/.steam/steam"
export WINEDLLOVERRIDES="ucrtbase=n,b"
GAME="$HOME/2XKO/2XKO_modded/Live"
PROTON="$HOME/.steam/steam/steamapps/common/Proton - Experimental/proton"
EXE="$GAME/Lion/Binaries/Win64/Lion-Win64-Shipping.exe"
B="$STEAM_COMPAT_DATA_PATH/pfx/drive_c/users/steamuser/AppData/Local/Lion/Saved/Logs/Lion.log"

pkill -9 -f wine 2>/dev/null
sleep 3
rm -f "$B"
LOG=/tmp/long.log
: > "$LOG"
( cd "$GAME" && timeout 200 "$PROTON" waitforexitandrun "$EXE" -disconnectedsupport-enable >"$LOG" 2>&1 ) &
for s in 30 60 90 120 150 180; do
    sleep 10
    echo "t~=${s}s  log=$(stat -c%s "$B" 2>/dev/null || echo 0) bytes"
done
echo "--- last 10 log lines ---"
tail -n 10 "$B" 2>/dev/null
echo "--- state transitions ---"
grep -a 'FREGameModeState::' "$B" 2>/dev/null | tail -n 6
pkill -f 'Lion-Win64' 2>/dev/null

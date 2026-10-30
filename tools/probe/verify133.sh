#!/usr/bin/env bash
# verify133.sh - relaunch the rebuilt exe and see whether FRE is skipped now.
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
: > /tmp/v133.log
( cd "$GAME" && timeout 200 "$PROTON" waitforexitandrun "$EXE" -disconnectedsupport-enable >/tmp/v133.log 2>&1 ) &

for i in $(seq 1 90); do
    sleep 1
    if grep -qa 'Mode.MainMenu\|WBP_Disconnected_Splash_C' "$B" 2>/dev/null; then
        echo "reached marker after ${i}s"
        break
    fi
done
sleep 8
echo "--- FRE states (none = FRE skipped) ---"
grep -a 'FREGameModeState::' "$B" 2>/dev/null | tail -n 6 | cut -c1-130
echo "--- major mode / maps ---"
grep -aE 'EnterMajorMode|Bringing World|Game class' "$B" 2>/dev/null | tail -n 6 | cut -c1-130
echo "--- modals ---"
grep -a 'Showed modal\|Focused desired target' "$B" 2>/dev/null | tail -n 4 | cut -c1-120
echo "--- last 4 ---"
tail -n 4 "$B" 2>/dev/null | cut -c1-140

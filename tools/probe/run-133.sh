#!/usr/bin/env bash
# run-133.sh - launch the unpacked 2XKO 1.3.3 build offline under Proton.
#
# Offline only. The prefix has a local stub registered as the "vgc" service that
# answers the Vanguard pipe handshake (see setup-vgc.sh); without it the game shows
# "VANGUARD ERROR: VAN-83" and will not leave the main menu.
#
# Automatic keypresses (XTEST via key133.py, no xdotool needed):
#   1. FRE prompt: "UNABLE TO ESTABLISH CONNECTION FOR LOGIN. PROCEED IN OFFLINE MODE?"
#      (OK is focused, so Enter)
#   2. the title screen ("press any button")
#
#   ./run-133.sh            normal launch
#   ./run-133.sh --no-auto  launch without the automatic keypresses
set -u
export XDG_RUNTIME_DIR=/run/user/1000
export DISPLAY="${DISPLAY:-:0}"
export WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-wayland-1}"
export STEAM_COMPAT_DATA_PATH="$HOME/2XKO/.prefix-133"
export STEAM_COMPAT_CLIENT_INSTALL_PATH="$HOME/.steam/steam"
export WINEDLLOVERRIDES="ucrtbase=n,b"

GAME="$HOME/2XKO/2XKO_modded/Live"
PROTON="$HOME/.steam/steam/steamapps/common/Proton - Experimental/proton"
WINE="$HOME/.steam/steam/steamapps/common/Proton - Experimental/files/bin/wine"
EXE="$GAME/Lion/Binaries/Win64/Lion-Win64-Shipping.exe"
B="$STEAM_COMPAT_DATA_PATH/pfx/drive_c/users/steamuser/AppData/Local/Lion/Saved/Logs/Lion.log"
KEY="$(dirname "$0")/key133.py"

AUTO=1
[ "${1:-}" = "--no-auto" ] && AUTO=0

press() { python3 "$KEY" "${1:-Return}" >/dev/null 2>&1 || true; }
has() { grep -qa "$1" "$B" 2>/dev/null; }

cd "$GAME" || exit 1
# keep the previous run's log around: it is the only record of a failed match start
cp -f "$B" /tmp/Lion-previous.log 2>/dev/null
rm -f "$B"
"$PROTON" waitforexitandrun "$EXE" -disconnectedsupport-enable &
GAME_PID=$!

if [ "$AUTO" = 1 ]; then
    (
        for _ in $(seq 1 180); do
            sleep 1
            has 'CheckDisconnectedSupport' || continue
            for _ in 1 2 3 4 5 6; do
                sleep 3
                press Return
                sleep 2
                has 'RequireOnlinePlatform' && break 2
            done
        done
        for _ in $(seq 1 60); do
            sleep 2
            has 'Mode.MainMenu' && break
            has 'Mode.Game' && break
            has 'Showed modal WBP_SingleButtonModalWidget_C' && break
            if has 'WBP_TitleSplash' || has 'WBP_TitleScreen_C'; then
                press Space
            fi
        done
    ) &
    AUTOPID=$!
fi

wait $GAME_PID
[ "$AUTO" = 1 ] && kill "$AUTOPID" 2>/dev/null
# leave no orphaned CEF/crashpad/wineserver children behind (they add real load)
WINEPREFIX="$STEAM_COMPAT_DATA_PATH/pfx" "$WINE" wineserver -k 2>/dev/null
killall -q vService crashpad_handler EpicWebHelper 2>/dev/null
exit 0

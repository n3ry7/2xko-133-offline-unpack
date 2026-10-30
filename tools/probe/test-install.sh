#!/usr/bin/env bash
# test-install.sh - install the rebuilt exe on the ThinkPad and run it with +seh.
# Unlike test-up3.sh this copies ~/2XKO/unpacked-133.exe into place first.
set -u
export XDG_RUNTIME_DIR=/run/user/1000
export DISPLAY=:0
export WAYLAND_DISPLAY=wayland-1
export STEAM_COMPAT_DATA_PATH="$HOME/2XKO/.prefix-133"
export STEAM_COMPAT_CLIENT_INSTALL_PATH="$HOME/.steam/steam"
export WINEDLLOVERRIDES="ucrtbase=n,b"
W="$HOME/2XKO/2XKO_modded/Live/Lion/Binaries/Win64"
GAME="$HOME/2XKO/2XKO_modded/Live"
PROTON="$HOME/.steam/steam/steamapps/common/Proton - Experimental/proton"
EXE="$W/Lion-Win64-Shipping.exe"
BASE="$STEAM_COMPAT_DATA_PATH/pfx/drive_c/users/steamuser/AppData/Local/Lion"

[ -f "$EXE.packed" ] || cp "$EXE" "$EXE.packed"
cp "$HOME/2XKO/unpacked-133.exe" "$EXE"
echo "installed: $(sha256sum "$EXE" | cut -c1-16)  size $(stat -c%s "$EXE")"
echo "backup   : $(sha256sum "$EXE.packed" | cut -c1-16)"

pkill -9 -f wine 2>/dev/null
rm -rf /tmp/.wine-1000
sleep 4
rm -rf "$BASE/Saved/Logs"

LOG=/tmp/inst.log
: > "$LOG"
( cd "$GAME" && WINEDEBUG=+seh timeout 60 "$PROTON" waitforexitandrun "$EXE" -disconnectedsupport-enable >"$LOG" 2>&1 )
echo "rc=$? lines=$(wc -l <"$LOG")"
echo "Lion.log: $(ls -l "$BASE/Saved/Logs/Lion.log" 2>/dev/null | awk '{print $5}') bytes"

echo "--- exceptions ---"
grep -a 'dispatch_exception code=' "$LOG" | sed 's/.*code=//; s/ .*//' | sort | uniq -c
echo "--- AV rips ---"
grep -a 'dispatch_exception code=c0000005' "$LOG" | sed 's/.*addr=//' | sort -u | head -n 5
echo "--- last 12 lines ---"
tail -n 12 "$LOG" | cut -c1-170

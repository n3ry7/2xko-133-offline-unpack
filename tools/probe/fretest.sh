#!/usr/bin/env bash
# fretest.sh - run the rebuilt exe on the ThinkPad and press OK on the offline-mode
# prompt ("UNABLE TO ESTABLISH CONNECTION FOR LOGIN") without xdotool, using
# XTEST through ctypes from python3.
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
B="$STEAM_COMPAT_DATA_PATH/pfx/drive/users/steamuser/AppData/Local/Lion/Saved/Logs/Lion.log"
B="$STEAM_COMPAT_DATA_PATH/pfx/drive_c/users/steamuser/AppData/Local/Lion/Saved/Logs/Lion.log"

pkill -9 -f wine 2>/dev/null
sleep 3
rm -f "$B"
: > /tmp/fre2.log
( cd "$GAME" && timeout 180 "$PROTON" waitforexitandrun "$EXE" -disconnectedsupport-enable >/tmp/fre2.log 2>&1 ) &

for i in $(seq 1 240); do
    sleep 1
    if grep -qa 'WBP_Disconnected_Splash_C' "$B" 2>/dev/null; then
        echo "splash after ${i}s"
        break
    fi
done

sleep 2
python3 - <<'PY'
import ctypes, time
x11 = ctypes.CDLL('libX11.so.6')
xtst = ctypes.CDLL('libXtst.so.6')
x11.XOpenDisplay.restype = ctypes.c_void_p
x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
xtst.XTestFakeKeyEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
x11.XFlush.argtypes = [ctypes.c_void_p]
x11.XGetInputFocus.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_int)]
d = x11.XOpenDisplay(None)
if not d:
    raise SystemExit('no display')
w = ctypes.c_ulong(); rev = ctypes.c_int()
x11.XGetInputFocus(d, ctypes.byref(w), ctypes.byref(rev))
print('focused window:', hex(w.value))
for code in (36,):            # 36 = Return
    xtst.XTestFakeKeyEvent(d, code, 1, 0); x11.XFlush(d); time.sleep(0.08)
    xtst.XTestFakeKeyEvent(d, code, 0, 0); x11.XFlush(d); time.sleep(0.3)
print('sent Return')
PY

sleep 12
echo "--- FRE states ---"
grep -a 'FREGameModeState::' "$B" 2>/dev/null | tail -n 6
echo "--- major mode / map ---"
grep -aE 'MajorMode|Bringing World|LogLoad: Game class' "$B" 2>/dev/null | tail -n 5
echo "--- last 5 ---"
tail -n 5 "$B" 2>/dev/null | cut -c1-150
echo "--- still running? ---"
pgrep -fa 'Lion-Win64' | head -n 2

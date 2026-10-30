export DISPLAY=:0 XDG_RUNTIME_DIR=/run/user/1000 WAYLAND_DISPLAY=wayland-1
python3 - <<'PY'
import ctypes
x11 = ctypes.CDLL('libX11.so.6')
x11.XOpenDisplay.restype = ctypes.c_void_p
x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
d = x11.XOpenDisplay(None)
print('X display:', 'OK' if d else 'DENIED (needs XAUTHORITY)')
PY
pgrep -a Xwayland | head -n 1
#!/usr/bin/env bash
# press2.sh - list X windows, focus the game window, press Return, report FRE state.
set -u
export DISPLAY=:0
export XDG_RUNTIME_DIR=/run/user/1000
B="$HOME/2XKO/.prefix-133/pfx/drive_c/users/steamuser/AppData/Local/Lion/Saved/Logs/Lion.log"

python3 - <<'PY'
import ctypes, time

x11 = ctypes.CDLL('libX11.so.6')
xtst = ctypes.CDLL('libXtst.so.6')

class Display(ctypes.Structure):
    pass

x11.XOpenDisplay.restype = ctypes.c_void_p
x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
x11.XDefaultRootWindow.restype = ctypes.c_ulong
x11.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
x11.XQueryTree.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                           ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong),
                           ctypes.POINTER(ctypes.POINTER(ctypes.c_ulong)), ctypes.POINTER(ctypes.c_uint)]
x11.XFetchName.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_char_p)]
x11.XGetClassHint.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
x11.XSetInputFocus.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
x11.XRaiseWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
x11.XFlush.argtypes = [ctypes.c_void_p]
x11.XGetInputFocus.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_int)]
xtst.XTestFakeKeyEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]
xtst.XTestFakeButtonEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]

d = x11.XOpenDisplay(None)
root = x11.XDefaultRootWindow(d)


def children(w):
    r, p = ctypes.c_ulong(), ctypes.c_ulong()
    ch = ctypes.POINTER(ctypes.c_ulong)()
    n = ctypes.c_uint()
    if not x11.XQueryTree(d, w, ctypes.byref(r), ctypes.byref(p), ctypes.byref(ch), ctypes.byref(n)):
        return []
    return [ch[i] for i in range(n.value)]


def name(w):
    s = ctypes.c_char_p()
    if x11.XFetchName(d, w, ctypes.byref(s)) and s.value:
        return s.value.decode('latin-1')
    return ''


seen = []


def walk(w, depth=0):
    seen.append((depth, w, name(w)))
    if depth >= 2:
        return
    for c in children(w):
        walk(c, depth + 1)


walk(root)
for depth, w, nm in seen:
    if nm:
        print(f'{"  " * depth}{w:#x}  {nm[:80]}')

# the game window: Wine usually names it after the exe/title
match = [w for _, w, nm in seen if nm and ('lion' in nm.lower() or '2xko' in nm.lower() or 'shipping' in nm.lower())]
cur = ctypes.c_ulong(); rev = ctypes.c_int()
x11.XGetInputFocus(d, ctypes.byref(cur), ctypes.byref(rev))
print('current focus:', hex(cur.value))
if match:
    target = match[0]
    print('target:', hex(target), name(target))
    x11.XRaiseWindow(d, target)
    x11.XSetInputFocus(d, target, 1, 0)   # RevertToPointerRoot
    x11.XFlush(d)
    time.sleep(0.5)
    x11.XGetInputFocus(d, ctypes.byref(cur), ctypes.byref(rev))
    print('focus now:', hex(cur.value))

for label, code in (('Return', 36),):
    xtst.XTestFakeKeyEvent(d, code, 1, 0); x11.XFlush(d); time.sleep(0.1)
    xtst.XTestFakeKeyEvent(d, code, 0, 0); x11.XFlush(d); time.sleep(0.4)
    print('sent', label)

# also click the OK button in the middle of the screen as a fallback
xtst.XTestFakeMotionEvent = None
PY

sleep 6
echo "--- FRE states ---"
grep -a 'FREGameModeState::' "$B" 2>/dev/null | tail -n 4

#!/usr/bin/env python3
"""key133.py - press a key on the X display without xdotool (XTEST).

The offline-mode prompt ("UNABLE TO ESTABLISH CONNECTION FOR LOGIN") has its OK
button focused, so Enter is enough. Needs only libX11 + libXtst, both present.

    python3 key133.py [Return|Space]
"""
import ctypes
import sys
import time

CODES = {'Return': 36, 'Space': 65, 'Escape': 9}
name = sys.argv[1] if len(sys.argv) > 1 else 'Return'
code = CODES[name]

x11 = ctypes.CDLL('libX11.so.6')
xtst = ctypes.CDLL('libXtst.so.6')
x11.XOpenDisplay.restype = ctypes.c_void_p
x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
x11.XFlush.argtypes = [ctypes.c_void_p]
xtst.XTestFakeKeyEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int,
                                   ctypes.c_ulong]

d = x11.XOpenDisplay(None)
if not d:
    raise SystemExit('key133: no X display')
xtst.XTestFakeKeyEvent(d, code, 1, 0)
x11.XFlush(d)
time.sleep(0.08)
xtst.XTestFakeKeyEvent(d, code, 0, 0)
x11.XFlush(d)
print(f'key133: sent {name}', flush=True)

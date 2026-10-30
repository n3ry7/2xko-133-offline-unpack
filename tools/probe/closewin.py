#!/usr/bin/env python3
"""Close orphaned Wine/game X windows. Errors are ignored (async X protocol)."""
import ctypes
import time

x11 = ctypes.CDLL('libX11.so.6')
x11.XOpenDisplay.restype = ctypes.c_void_p
x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
x11.XDefaultRootWindow.restype = ctypes.c_ulong
x11.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
x11.XQueryTree.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong),
                           ctypes.POINTER(ctypes.c_ulong),
                           ctypes.POINTER(ctypes.POINTER(ctypes.c_ulong)),
                           ctypes.POINTER(ctypes.c_uint)]
x11.XFetchName.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_char_p)]
x11.XKillClient.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
x11.XDestroyWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
x11.XSync.argtypes = [ctypes.c_void_p, ctypes.c_int]

ERRHANDLER = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
handler = ERRHANDLER(lambda d, e: 0)          # ignore X errors instead of aborting
x11.XSetErrorHandler.restype = ctypes.c_void_p
x11.XSetErrorHandler.argtypes = [ERRHANDLER]
x11.XSetErrorHandler(handler)

d = x11.XOpenDisplay(None)
root = x11.XDefaultRootWindow(d)


def tops():
    r, p = ctypes.c_ulong(), ctypes.c_ulong()
    ch = ctypes.POINTER(ctypes.c_ulong)()
    n = ctypes.c_uint()
    x11.XQueryTree(d, root, ctypes.byref(r), ctypes.byref(p), ctypes.byref(ch), ctypes.byref(n))
    out = []
    for i in range(n.value):
        s = ctypes.c_char_p()
        nm = ''
        if x11.XFetchName(d, ch[i], ctypes.byref(s)) and s.value:
            nm = s.value.decode('latin-1')
        out.append((ch[i], nm))
    return out


targets = [w for w, nm in tops() if nm.strip().lower() in ('lion', 'input')]
print('closing:', [hex(w) for w in targets], flush=True)
for w in targets:
    x11.XKillClient(d, w)          # kill the (already dead) client owning it
    x11.XDestroyWindow(d, w)       # and the window itself
x11.XSync(d, 0)
time.sleep(2)
left = [(hex(w), nm) for w, nm in tops() if nm.strip() and nm.strip().lower() in ('lion', 'input')]
print('still open:', left if left else 'none')

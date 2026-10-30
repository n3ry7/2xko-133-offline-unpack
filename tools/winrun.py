"""winrun.py - launch the rebuilt exe on Windows, answer the prompts, report the flow.

Mirrors run-133.sh on the ThinkPad: Enter at the offline-mode prompt, Space at the
title screen. Never touches the Vanguard EXIT GAME modal.

    python winrun.py [seconds]
"""
import ctypes
import os
import subprocess
import sys
import time

GAME = r'C:\Riot Games\2XKO_modded\Live'
EXE = os.path.join(GAME, r'Lion\Binaries\Win64\Lion-Win64-Shipping.exe')
LOG = os.path.join(os.environ['LOCALAPPDATA'], r'Lion\Saved\Logs\Lion.log')
u = ctypes.WinDLL('user32', use_last_error=True)

MARKS = [
    ('CheckDisconnectedSupport', 'offline prompt'),
    ('RequireOnlinePlatform', 'FRE advanced'),
    ('WBP_TitleSplash', 'title screen'),
    ('Mode.MainMenu', 'main menu'),
]


def log():
    try:
        with open(LOG, 'rb') as f:
            return f.read().decode('utf-8', 'replace')
    except OSError:
        return ''


def key(vk):
    u.keybd_event(vk, 0, 0, 0)
    time.sleep(0.06)
    u.keybd_event(vk, 0, 2, 0)


def main():
    limit = float(sys.argv[1]) if len(sys.argv) > 1 else 150
    try:
        os.remove(LOG)
    except OSError:
        pass
    p = subprocess.Popen([EXE, '-disconnectedsupport-enable'], cwd=GAME)
    print('pid', p.pid, flush=True)
    seen = set()
    t0 = time.time()
    pressed_prompt = pressed_title = False
    while time.time() - t0 < limit and p.poll() is None:
        txt = log()
        for mark, label in MARKS:
            if mark in txt and mark not in seen:
                seen.add(mark)
                print(f'  t={time.time()-t0:5.1f}s  {label}  ({mark})', flush=True)
        if 'CheckDisconnectedSupport' in seen and not pressed_prompt:
            time.sleep(2.5)
            key(0x0D)              # Enter -> OK
            pressed_prompt = True
            print(f'  t={time.time()-t0:5.1f}s  sent Enter (offline prompt)', flush=True)
        if 'WBP_TitleSplash' in seen and not pressed_title and 'Mode.MainMenu' not in seen:
            time.sleep(1.5)
            key(0x20)              # Space -> press any button
            pressed_title = True
            print(f'  t={time.time()-t0:5.1f}s  sent Space (title screen)', flush=True)
        if 'Mode.MainMenu' in seen:
            time.sleep(6)
            break
        time.sleep(0.4)

    txt = log()
    print('reached:', [l for m, l in MARKS if m in txt])
    for pat in ('Queued modal', 'Showed modal', 'VanguardFaulted', 'RequestExit'):
        hits = [l for l in txt.splitlines() if pat in l]
        if hits:
            print(f'{pat}: {hits[-1][:110]}')
    ec = p.poll()
    if ec is None:
        print('still running (killing)')
        p.terminate()
    else:
        print('exited', ec)
    return 0


if __name__ == '__main__':
    sys.exit(main())

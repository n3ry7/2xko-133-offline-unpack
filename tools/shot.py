"""shot.py - start the game, wait for the FRE disconnected splash, screenshot it.

Leaves the game running so a key or click can be sent afterwards. No input is sent
by this script.

    python shot.py [out.png]
"""
import ctypes
import os
import subprocess
import sys
import time

GAME = r'C:\Riot Games\2XKO_modded\Live'
EXE = os.path.join(GAME, r'Lion\Binaries\Win64\Lion-Win64-Shipping.exe')
LOG = os.path.join(os.environ['LOCALAPPDATA'], r'Lion\Saved\Logs\Lion.log')
OUT = sys.argv[1] if len(sys.argv) > 1 else r'C:\2XKO-unpack\shot\splash.png'
MARK = 'WBP_Disconnected_Splash_C'


def log_text():
    try:
        with open(LOG, 'rb') as f:
            return f.read().decode('utf-8', 'replace')
    except OSError:
        return ''


def tail(n=6):
    lines = log_text().splitlines()
    return '\n'.join(l[:150] for l in lines[-n:])


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    try:
        os.remove(LOG)
    except OSError:
        pass
    p = subprocess.Popen([EXE, '-disconnectedsupport-enable'], cwd=GAME)
    print(f'pid {p.pid}', flush=True)

    deadline = time.time() + 150
    seen = False
    while time.time() < deadline:
        if p.poll() is not None:
            print('process exited early, rc', p.returncode)
            print(tail(10))
            return 2
        if MARK in log_text():
            seen = True
            break
        time.sleep(0.25)
    print('splash reached:', seen, flush=True)
    time.sleep(3.0)

    ps = (
        'Add-Type -AssemblyName System.Windows.Forms,System.Drawing;'
        '$b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds;'
        '$bmp=New-Object Drawing.Bitmap $b.Width,$b.Height;'
        '$g=[Drawing.Graphics]::FromImage($bmp);'
        '$g.CopyFromScreen($b.Location,[Drawing.Point]::Empty,$b.Size);'
        f'$bmp.Save("{OUT}",[Drawing.Imaging.ImageFormat]::Png);'
        'Write-Output "$($b.Width)x$($b.Height)"'
    )
    r = subprocess.run(['powershell', '-NoProfile', '-Command', ps],
                       capture_output=True, text=True)
    print('screen:', r.stdout.strip(), r.stderr.strip()[:200])
    print('saved:', OUT, os.path.getsize(OUT) if os.path.exists(OUT) else 'MISSING')
    print('alive:', p.poll() is None)
    print('--- log tail ---')
    print(tail(8))
    return 0


if __name__ == '__main__':
    sys.exit(main())

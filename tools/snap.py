"""snap.py - capture the primary screen to a PNG (no input is sent).

    python snap.py C:\\path\\out.png
"""
import os
import subprocess
import sys

out = sys.argv[1] if len(sys.argv) > 1 else r'C:\2XKO-unpack\shot\snap.png'
os.makedirs(os.path.dirname(out), exist_ok=True)
ps = (
    'Add-Type -AssemblyName System.Windows.Forms,System.Drawing;'
    '$b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds;'
    '$bmp=New-Object Drawing.Bitmap $b.Width,$b.Height;'
    '$g=[Drawing.Graphics]::FromImage($bmp);'
    '$g.CopyFromScreen($b.Location,[Drawing.Point]::Empty,$b.Size);'
    '$bmp.Save(' + "'" + out + "'" + ',[Drawing.Imaging.ImageFormat]::Png)'
)
r = subprocess.run(['powershell', '-NoProfile', '-Command', ps],
                   capture_output=True, text=True)
if not os.path.exists(out):
    print('FAILED', r.stderr[:300])
    sys.exit(1)
print('saved', out, os.path.getsize(out))

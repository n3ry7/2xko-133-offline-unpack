# run-remote.ps1 - one launch, then remote3.py, attached during startup.
#
#   powershell -ExecutionPolicy Bypass -File C:\2XKO-unpack\run-remote.ps1
#
# Preconditions: vgk STOPPED (admin), no game process running, nothing typed at
# the game window (the VAN modal's only button is EXIT GAME).
#
# No existing thread is touched: remote3.py only uses CreateRemoteThread with a
# stub whose destination addresses are baked in, so no register convention can
# be wrong. hijack*.py is deliberately NOT run again - it crashed the game.
param(
    [int]$SettleSec = 8,
    [string]$Script = 'remote3',
    [string]$ProbeArgs = ''
)

$ErrorActionPreference = 'Continue'
$unpack = 'C:\2XKO-unpack'
$live = 'C:\Riot Games\2XKO_modded\Live'
$log = "$env:LOCALAPPDATA\Lion\Saved\Logs\Lion.log"

function Section($t) { ""; "=== $t" }

Section 'preconditions'
$vgk = (sc.exe query vgk | Select-String 'STATE').ToString().Trim()
"vgk: $vgk"
if ($vgk -notmatch 'STOPPED') {
    "ABORT: vgk is still loaded - OpenProcess will be denied."
    "Run an elevated: sc.exe stop vgk"
    exit 3
}
$exe = "$live\Lion\Binaries\Win64\Lion-Win64-Shipping.exe"
"exe sha256: $((Get-FileHash $exe -Algorithm SHA256).Hash)"
"free GB:    $([math]::Round((Get-Volume -DriveLetter C).SizeRemaining/1GB,2))"
if (Get-Process Lion-Win64-Shipping -ErrorAction SilentlyContinue) {
    "ABORT: a game process is already running."
    exit 3
}

Section 'launch'
Remove-Item $log -Force -ErrorAction SilentlyContinue
$p = Start-Process -FilePath "$live\OfflineLauncher.exe" -WorkingDirectory $live -PassThru
"launcher pid $($p.Id) at $(Get-Date -Format HH:mm:ss)"

$deadline = (Get-Date).AddSeconds(180)
while (-not (Get-Process Lion-Win64-Shipping -ErrorAction SilentlyContinue)) {
    if ((Get-Date) -gt $deadline) { "ABORT: game process never appeared"; exit 4 }
    Start-Sleep -Milliseconds 500
}
$g = Get-Process Lion-Win64-Shipping
"game pid $($g.Id) appeared at $(Get-Date -Format HH:mm:ss)"
Start-Sleep -Seconds $SettleSec

Section "remote3 ($Script)"
Push-Location $unpack
foreach ($s in $Script.Split(',')) {
    "--- $s"
    $al = @(); if ($ProbeArgs) { $al = $ProbeArgs -split '\s+' }
    python "$s.py" Lion-Win64-Shipping @al 2>&1 | Where-Object { $_ -notmatch '^\s*$' }
    $rc = $LASTEXITCODE
}
Pop-Location

Section 'process state after probe'
$g = @(Get-Process Lion-Win64-Shipping -ErrorAction SilentlyContinue) | Select-Object -First 1
if ($g) {
    "alive: pid $($g.Id)  WS $([math]::Round($g.WorkingSet64/1GB,2)) GB"
} else {
    "dead - last log lines:"
    if (Test-Path $log) { Get-Content $log -Tail 12 }
}
exit $rc

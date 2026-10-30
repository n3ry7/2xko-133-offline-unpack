# auto.ps1 - unattended decrypt runs until .text is complete.
#
# Each cycle: make sure a game process exists (waiting for the packer to go
# idle), then run tfwalk.py from the page recorded in textdump/next.txt. The
# walker saves state every 10 pages, so a crash costs at most a few pages.
#
#   powershell -ExecutionPolicy Bypass -File C:\2XKO-unpack\auto.ps1
#
# Stop with Ctrl+C; state is on disk and a later run continues.
param(
    [int]$SettleSec = 115,
    [int]$MaxCycles = 400,
    [int]$SkipAfterStall = 20
)

$ErrorActionPreference = 'Continue'
$unpack = 'C:\2XKO-unpack'
$live = 'C:\Riot Games\2XKO_modded\Live'
$nextFile = "$unpack\textdump\next.txt"

function Get-Next { if (Test-Path $nextFile) { [int](Get-Content $nextFile -Raw).Trim() } else { 0 } }
function Dumped {
    $path = "$unpack\textdump\dumped.bin"
    if (-not (Test-Path $path)) { return 0 }
    $b = [IO.File]::ReadAllBytes($path)
    $n = 0
    foreach ($x in $b) { if ($x) { $n++ } }
    $n
}

$stall = 0
for ($cycle = 1; $cycle -le $MaxCycles; $cycle++) {
    $vgk = (sc.exe query vgk | Select-String 'STATE').ToString()
    if ($vgk -notmatch 'STOPPED') { "vgk is not stopped - stopping"; break }

    $proc = @(Get-Process Lion-Win64-Shipping -ErrorAction SilentlyContinue) | Select-Object -First 1
    if (-not $proc) {
        "=== cycle $cycle : launching at $(Get-Date -Format HH:mm:ss)"
        Start-Process -FilePath "$live\OfflineLauncher.exe" -WorkingDirectory $live | Out-Null
        $deadline = (Get-Date).AddSeconds(180)
        while (-not (@(Get-Process Lion-Win64-Shipping -ErrorAction SilentlyContinue) | Select-Object -First 1)) {
            if ((Get-Date) -gt $deadline) { "launch timed out"; break }
            Start-Sleep -Milliseconds 500
        }
        if (-not (@(Get-Process Lion-Win64-Shipping -ErrorAction SilentlyContinue) | Select-Object -First 1)) {
            Start-Sleep -Seconds 10
            continue
        }
        Start-Sleep -Seconds $SettleSec
    }

    $before = Dumped
    $next = Get-Next
    "=== cycle $cycle : start $next, dumped $before"
    Push-Location $unpack
    # registration loses a race with the packer sometimes; retry on the same
    # process before burning a whole relaunch
    for ($try = 1; $try -le 3; $try++) {
        $before = Dumped
        $next = Get-Next
        python tfwalk8.py Lion-Win64-Shipping --start $next --pages 40000 2>&1 |
            Where-Object { $_ -match 'registered|PACER|dumped|PROCESS DIED|run:|total|died|never' } |
            Select-Object -Last 6
        if ($LASTEXITCODE -eq 9) { "    pacer: relaunching"; break }
        if ((Dumped) -gt $before) { break }
        $alive = @(Get-Process Lion-Win64-Shipping -ErrorAction SilentlyContinue) | Select-Object -First 1
        if (-not $alive) { break }
        "    retry $try on the same process"
        Start-Sleep -Seconds 15
    }
    Pop-Location

    $after = Dumped
    $newNext = Get-Next
    "    cycle $cycle done: dumped $after (+$($after - $before)), next $newNext"

    if ($after -ge 32784) { "ALL PAGES DUMPED"; break }

    # at the end of .text, wrap around for another pass over skipped pages
    if ($newNext -ge 32784) { Set-Content $nextFile 0 -NoNewline; "    wrapped to page 0 for another pass" }

    if ($after -eq $before) {
        $stall++
        "    no progress (stall $stall)"
        if ($stall -ge 2) {
            $bump = [Math]::Min($newNext + $SkipAfterStall, 32784)
            "    skipping ahead to $bump"
            Set-Content $nextFile $bump -NoNewline
            $stall = 0
        }
    } else { $stall = 0 }

    $alive = @(Get-Process Lion-Win64-Shipping -ErrorAction SilentlyContinue) | Select-Object -First 1
    if ($alive) { Stop-Process -Id $alive.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 4
}
"=== auto.ps1 finished: $(Dumped) / 32784 pages"

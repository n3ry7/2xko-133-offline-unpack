# 2XKO 1.3.3 offline build - WORKING

_Last updated: 2026-10-30, after training mode was confirmed playable on the ThinkPad._

## Status

Unpacked and playable offline on the ThinkPad under Proton, and on Windows.

| | Windows | ThinkPad (Proton) |
|---|---|---|
| boots / engine init | yes | yes |
| FRE -> title -> main menu | yes (one Enter) | yes (automatic) |
| Vanguard | ok while `vgk` runs | satisfied by local `vgc` stub |
| **training** | - | **yes, confirmed** |
| versus | - | being tested |

Final exe: `C:\2XKO-unpack\unpacked-133.exe`, 195,327,488 bytes, sha256 prefix
`866f45f2`. Installed on the ThinkPad at
`~/2XKO/2XKO_modded/Live/Lion/Binaries/Win64/Lion-Win64-Shipping.exe`
(original kept as `Lion-Win64-Shipping.exe.packed`, prefix `bf9a7e97`).

## How to play (ThinkPad)

    ~/2XKO/run-133.sh

It launches the game, answers the offline prompt and the title screen (XTEST via
`key133.py`, no xdotool), and on exit shuts the prefix down cleanly.

**Do not run it while the game is already running** - it ends any existing Wine session
first.

## The three pieces that made it work

1. **Unpack** - `.text` decrypted page by page with a fault-walker that only accepts a
   page once two consecutive reads agree (the packer flips a page to RX before the
   plaintext write finishes). OEP `0x7e698b0`, IAT at `0x8011000`, 1,214 imports.
2. **Bootstrap** (`mkboot.py`) - the rebuilt exe has **no import directory**; Windows
   silently ignored the one we synthesised. Instead the stub walks
   `PEB -> Ldr -> InLoadOrderModuleList` for the module exporting `KERNEL32`, parses its
   export table for `LoadLibraryA`/`GetProcAddress`, fills all 1,214 packer IAT slots,
   then jumps to the OEP. Verified on Windows and Wine.
3. **Vanguard** - the game stopped at the main menu with "VANGUARD ERROR: VAN-83"
   because `LogLionVanguard: Initializing Vanguard client.` could not reach Vanguard.
   The SDK talks to `\\.\pipe\933823D3-C77B-4BAE-89D7-A92B567236BC`; a stub service
   (`vService.exe`, from the earlier session) answers the login + heartbeat exchange.
   Installed once in the prefix as the `vgc` service; Wine's services.exe auto-starts it:

       PFX=~/2XKO/.prefix-133/pfx
       # binary at $PFX/drive_c/vanguard/vService.exe
       # registry key [System\CurrentControlSet\Services\vgc] in $PFX/system.reg
       #   ImagePath="C:\\vanguard\\vService.exe"  Start=2  Type=0x10
       # reinstall with:  bash probe/setup-vgc.sh   (needs wineserver stopped)

   Keys in a Wine `.reg` file need **doubled** backslashes; a single-backslash key gets
   misparsed and the service silently never starts.

**Offline only.** This setup never talks to Riot services and online play is not
possible from it - which is the intended use.

## Gotchas seen along the way

- The "blocker" at `CheckDisconnectedSupport` was just an unclicked dialog:
  "UNABLE TO ESTABLISH CONNECTION FOR LOGIN. PROCEED IN OFFLINE MODE AS ...?" with OK
  already focused. FRE re-runs on every launch, so it needs one keypress each time.
- The first "could not start a battle" was the machine at **load average 62** from
  orphaned `EpicWebHelper`/`crashpad`/`wine` processes left by killed test runs. The
  stage (`Stage_Thematic_ProjectRooftop`) had streamed but was crawling. Killing the
  orphans fixed it; `run-133.sh` now runs `wineserver -k` on exit.
- `pkill -f wine` matches its own shell command line and kills the session - use
  `killall -9 wine ...` instead.
- After logging out/in the X cookie changes: `XOpenDisplay` fails with
  "Authorization required" until you are logged back in.

## Rebuild

    cd C:\2XKO-unpack
    python rebuild2.py --out unpacked-133.exe   # textdump\text.bin + dumpimg\imports.json
    python mkboot.py                            # prints the stub disassembly (capstone)

`.boot` layout: code 0x000, slots 0x740/0x748, marker 0x750, handles 0x760,
module-name table 0x960, entries 0xa80, string pool after. Entry `0xbef8000`,
SizeOfImage `0xbf05000`.

## Tooling

- `dbgrun.py` - native debug loop (first-chance exceptions, RIP/RSP, module map)
- `winrun.py` - native end-to-end run (answers prompt + title screen)
- `snap.py` - screenshot helper
- `probe/run-133.sh`, `probe/key133.py` - ThinkPad launcher + XTEST keypress
- `probe/setup-vgc.sh` - install the vgc stub service in the prefix
- `probe/matchtest.sh`, `probe/vgctest.sh` - launch + walk into a match, report the log

## Windows box state

`Lion-Win64-Shipping.exe` restored to the **packed** original (`bf9a7e97`), no game
process. `vgk` is **stopped** (needed for dumping) - run `sc.exe start vgk` before
playing online.

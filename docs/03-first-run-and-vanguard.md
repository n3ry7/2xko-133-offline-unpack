# 3. First run (FRE) and Vanguard

## The "blocker" that was just a dialog

After the engine came up, the log always stopped at:

```
LogFREGameMode: Display: Advancing State to FREGameModeState::CheckDisconnectedSupport.
LogLionActivatableWidget: ... IMC_Splash registered for widget WBP_Disconnected_Splash_C
LogUIActionRouter: Display: [User 0] Focused desired target WBP_Modal_Btn
RGISaveLoadManager: ExecuteCompleted successfully on slot ActiveUser
```

and then nothing, forever. It looked like a platform-service deadlock (and under Wine
the earlier packed binary did die in `rpcrt4`). It was not: the game was showing a
modal with **OK already focused**:

```
UNABLE TO ESTABLISH CONNECTION FOR LOGIN.
PROCEED IN OFFLINE MODE AS <account>?
        [ OK ]
```

One Enter walks the whole first-run experience:

```
CheckDisconnectedSupport -> RequireOnlinePlatform -> AttractMode -> Complete -> Mode.MainMenu
```

FRE is **not persisted**: it runs on every launch. After it, the title screen needs one
"press any button".

Also worth knowing: the two names that look like the obvious fix,
`bAutomaticallyDismissFRE` and `bAlwaysShowFREOnLoading`, are **UPROPERTY names**, not
console variables (they sit in the name table next to `PlatformUIFREClassPtr`,
`RGIOPRestrictionInfoJwt`). Putting them in `[ConsoleVariables]` does nothing — the log
confirms `Engine.ini` was read (`Applying CVar settings from Section [ConsoleVariables]
File [Engine]`) and the values were simply ignored.

## Automating the keypress on Linux without xdotool

There is no `xdotool`/`xte` on the reference machine, but `python3` with `ctypes` can
drive XTEST directly through `libX11` + `libXtst`:

```python
x11.XOpenDisplay(None)
xtst.XTestFakeKeyEvent(display, 36, 1, 0)   # 36 = Return
x11.XFlush(display)
xtst.XTestFakeKeyEvent(display, 36, 0, 0)
```

`tools/probe/key133.py` implements that (Return/Space/Escape); `run-133.sh` polls the
game log and presses at the right moments:

1. wait for `CheckDisconnectedSupport`, then press Return until
   `RequireOnlinePlatform` appears (retries every ~5 s, because pressing too early is
   simply ignored)
2. wait for the title screen (`WBP_TitleSplash` / `WBP_TitleScreen_C`) and press Space
   **only until** `Mode.MainMenu` / `Mode.Game` is reached, and never while a
   single-button modal is on screen — one of those modals has **EXIT GAME** as its only
   button, so a stray Enter kills the game

## Vanguard (VAN-83)

At `Mode.MainMenu` the game logged:

```
LogLionVanguard: Initializing Vanguard client.
... ~19 s later ...
LogModalUILayer: Queued modal BP_VanguardFaultedModalContent_C.
```

and showed **VANGUARD ERROR: VAN-83** with a single **EXIT GAME** button, which blocks
the menu.

On Windows the same modal appears while the `vgk` service is stopped; with Vanguard
installed and running it does not appear.

### What the client actually wants

The Vanguard SDK is a named-pipe client:

```
\\.\pipe\933823D3-C77B-4BAE-89D7-A92B567236BC
```

A prior session built `vService.exe` (a small native service binary, version
1.90.0.0) which serves that pipe, plus a PowerShell prototype and a captured trace.
The exchange is small:

```
CONNECTED
RECV 63B type=2 : 64000000 3F000000 02000000 ... "OFFLINE" ... "com.riotgames.2xko"
SENT 36B       : E9030000 24000000 01000000 00000000 ...        (0x3E9)
RECV 40B type=1 : 03000000 28000000 01000000 ... 08000000 <n>    (heartbeat)
SENT 40B       : 04000000 28000000 01000000 ... 08000000 <n>     (ack)
```

Login is answered once, then heartbeats every ~10 s are acknowledged. That is enough
for the client to report success and for the game to leave the main menu.

### Installing it under Proton

`vService.exe` is a **Windows service** (it imports `StartServiceCtrlDispatcherW`), so
running it from a console just exits. Instead it is installed as the `vgc` service in
the prefix registry and Wine's `services.exe` auto-starts it at prefix boot
(`tools/probe/setup-vgc.sh`):

```bash
PFX=~/2XKO/.prefix-133/pfx
mkdir -p "$PFX/drive_c/vanguard"
cp vService.exe "$PFX/drive_c/vanguard/vService.exe"
# then add to $PFX/system.reg, with wineserver stopped:
#   [System\\CurrentControlSet\\Services\\vgc]
#   "ImagePath"="C:\\vanguard\\vService.exe"
#   "Start"=dword:00000002      ; auto
#   "Type"=dword:00000010       ; win32 own process
#   "ObjectName"="LocalSystem"
```

**The escaping matters.** Keys in a Wine `.reg` file need **doubled** backslashes. The
first attempt wrote `[System\CurrentControlSet\Services\vgc]`, which Wine parsed as
`SystemCurrentControlSetServices\vgc` — the service was registered under a nonsense key,
never started, and `reg query` reported "unable to find the specified registry key"
while the XML-ish dump still looked plausible. Diagnostic: `grep -A6 'Services\\\\vgc'
system.reg` and compare with `wine reg query`.

Result after the fix: `pgrep -fa vService` shows `C:\vanguard\vService.exe`, and no
`BP_VanguardFaultedModalContent_C` is queued. The game proceeds to character select.

## Starting a battle

The match does load: `LogLionLevelSpawner` streams
`/Stage_Thematic_ProjectRooftop/...` sublevels, then transitions
`StreamingLevels → MakingVisible`.

The first attempt "could not start a battle" because the machine was at **load average
62**: repeated `pkill -9` of test runs had left ~11 `EpicWebHelper`/`crashpad_handler`
children behind, and the level load was crawling. After cleaning them up, the same
steps reached training mode. `run-133.sh` now runs `wineserver -k` and kills the leftover
helpers on exit so this does not accumulate.

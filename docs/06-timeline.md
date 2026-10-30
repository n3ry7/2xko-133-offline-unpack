# 6. Timeline

Times are from the logs of a single long session; they are included because the order
of discoveries matters more than the clock.

## Before the start of this log

- The packed 1.3.3 exe refuses to run under Proton (silent exit after a service-manager
  RPC); 1.2.5, which is **not** packed, runs fine and becomes the reference.
- First full `.text` decrypt pass completed (32,784 pages), OEP found
  (`0x7e698b0`), IAT reconstructed (1,214 imports), rebuilt exe boots to `FRELevel`.

## Pass 1 was wrong

- The rebuild dies at `0x2ce0` on what looks like AVX-512. Reading the **live** packed
  process shows `sub rsp,0x88; vmovaps …` — plain AVX2. Dump is corrupt.
- Cause: the packer flips a page to `RX` before finishing the plaintext write; the
  dumper read too early. Pages the game decrypted itself are perfect (2,683 checked,
  0 differ).
- `tfwalk8.py` adds `stable_read()` (two identical reads, 5 ms apart). A clean second
  pass starts, but it is slow; the decision is made to rebuild from pass 1 plus the
  re-dumped head and fix pages as crashes reveal them.

## Windows: the rebuilt exe dies at RIP 0

- Native run: `0xc0000005` at offset 0, no `Lion.log`, only 4 modules loaded.
- `dbgrun.py` (a `DEBUG_PROCESS` loop) shows the return address on the stack is
  `.boot+0x49` and the `.boot` IAT is still all zeros.
- Experiment: point the import descriptor at `NOPE32.dll`. `CreateProcess` succeeds
  anyway → the loader is skipping the import directory entirely, silently.
- Import-directory size variations (40 → 80 bytes) change nothing.

## The PEB resolver

- `mkboot.py` is rewritten: no imports at all; walk `PEB → Ldr → InLoadOrderModuleList`,
  match the export name `KERNEL32`, parse the export table, find `LoadLibraryA` and
  `GetProcAddress`, fill all 1,214 slots, jump to the OEP.
- Forwarder risk checked offline: both functions are real code in Windows `kernel32`,
  Wine `kernel32` **and** Wine `kernelbase` (the latter's export name is lowercase,
  which would have mattered had it been used).
- Two encoding bugs found by reading the capstone dump: `[r13+rax*4]` needed an
  explicit zero displacement, and the slot stores used section offsets instead of RVAs.
- First ThinkPad run with the new stub faults at `0xbef810c` with fault address
  `0x140000740` — exactly the RVA/offset bug. Fixed, rebuilt, and the ThinkPad reaches
  `FRELevel` again, confirming parity with the previous build.

## Windows: it works now

- Native run with the fixed stub: 89 modules load (including `OpenColorIO_2_3.dll`),
  engine init proceeds, FRE level loads. The earlier "stall at D3D11" was the debug
  loop holding the process, not the exe.
- Then the real find: the game is not stuck at `CheckDisconnectedSupport` — it is showing
  **"UNABLE TO ESTABLISH CONNECTION FOR LOGIN. PROCEED IN OFFLINE MODE AS …?"** with OK
  focused. Screenshot taken with `snap.py`.
- One Enter: `CheckDisconnectedSupport → RequireOnlinePlatform → AttractMode → Complete
  → Mode.MainMenu`. Attract mode runs on the menu background.

## ThinkPad: same dialog, no keyboard tool

- No `xdotool`/`xte`. XTEST is driven through `ctypes` (`libX11` + `libXtst`).
- First attempt fails (pressed too early / wrong focus); the retry loop that presses
  until `RequireOnlinePlatform` appears works.
- FRE completes; the game reaches `Mode.MainMenu`; the launcher adds a Space press for
  the title screen.
- At the menu: **VANGUARD ERROR: VAN-83**, one button (EXIT GAME). Blocked.

## Vanguard

- `LogLionVanguard: Initializing Vanguard client.` → ~19 s → `Queued modal
  BP_VanguardFaultedModalContent_C`.
- Static xref hunting is a dead end in this build: log format strings and enum names are
  reached through tables, so `lea` xrefs do not exist. (`DynamicConfig.lion.vanguard.required`
  does have xrefs, but they are diagnostic string construction, not the gate.)
- The pipe handshake is the real mechanism:
  `\\.\pipe\933823D3-C77B-4BAE-89D7-A92B567236BC`.
- A prior session's `vService.exe` (native, service, serves that pipe) is installed as
  the `vgc` service in the prefix. First attempt fails because the registry key was
  written with single backslashes → Wine parsed a different key and never started the
  service.
- After correcting the escaping: `vService` runs, **no fault modal**, and the game
  reaches character select. Screenshot confirms the full roster.

## Battle

- First battle attempt: the stage (`Stage_Thematic_ProjectRooftop`) streams its
  sublevels, transitions `StreamingLevels → MakingVisible` three minutes later, then
  nothing.
- Root cause: the machine was at **load average 62** from orphaned
  `EpicWebHelper`/`crashpad_handler`/`wine` processes accumulated by repeated test runs
  that were killed with `pkill -9`.
- After cleaning up (load ~5) the same flow reaches **training mode** and is playable.
  Versus uses the same path.

## Afterwards

- Launcher hardened: preserves the previous log, never presses keys once the menu or a
  modal is up, and shuts the prefix down cleanly on exit.
- This document set written; tooling collected here.

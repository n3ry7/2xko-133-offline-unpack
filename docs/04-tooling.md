# 4. Tooling

All scripts are as used; paths inside them default to the original layout
(`C:\2XKO-unpack\…`) and are worth adjusting if you reuse them elsewhere.

## tools/ — core

| file | what it does |
|---|---|
| `pe_dis.py` | Minimal PE reader: section table, RVA↔file-offset mapping. Imported by everything else. |
| `faultprobe.py` | Process plumbing: open a target, find the main module base, describe sections, read/query memory, change protection, and the VEH registration primitives. The largest and most reused module. |
| `vehwalk.py` | Walks the vectored-exception-handler chain, patches handler entries, and reads/writes thread contexts (`CONTEXT` offsets, `TF`). |
| `vehtest.py` | Builds the tiny in-target stub that calls `AddVectoredExceptionHandler` and reports back through a shared slot. |
| `tfwalk8.py` | **The dumper.** Faults each page of `.text`, waits for the packer to decrypt, reads it with `stable_read()`, writes `textdump/text.bin` + resumable bitmap, and exits after 150 pages with no progress so a harness can relaunch. |
| `tfwalk6.py` | Earlier iteration of the walker; still the source of `find_host()` (locates a writable host page inside an image module) and the CPU/feature globals. |
| `findoep2.py` | Captures the original entry point by intercepting the first execution of the decrypted section and reading the context. |
| `buildimports.py` | Reconstructs the packer's IAT from a live image: walks sentinel-delimited blocks at `0x8011000`, resolves each slot to `module!name`, writes `dumpimg/imports.json`. |
| `mkboot.py` | **Generates the `.boot` bootstrap.** Hand-rolled x64 emitter with label/rip fixups, the PEB→kernel32 export resolver, the 1,214-slot fill loop, and a `capstone` dump of the result for review. Run it directly to print the stub. |
| `rebuild2.py` | **Builds the exe**: writes decrypted `.text`, sets section characteristics, appends `.boot`, repoints the entry point, updates `SizeOfImage`, zeroes the import directory. |
| `verify.py` | Compares every currently-readable page of the live process against `text.bin` (no faulting) — this is how "2,683 pages, 0 differ" was established. `--fix` repairs mismatches. |
| `checkpage.py` | Faults one specific page, waits, and diffs it against the dump. Used to prove the stable-read fix. |
| `readlive.py` | Reads a live page and the SIMD-level global; can force a page to decrypt by faulting it. |
| `recover.py` | Rebuilds the dump bitmap (`dumped.bin`) from `text.bin` if the state files are lost. |
| `auto.ps1` | Dumping harness: launch → walk → relaunch loop, with settle time, retries and wrap-around. |
| `run-remote.ps1` | Copies a probe to the Linux box over ssh and runs it (host is a placeholder — set your own). |

## tools/ — native debugging and automation

| file | what it does |
|---|---|
| `dbgrun.py` | Launches the exe with `DEBUG_PROCESS` and reports first-chance exceptions with `RIP`/`RSP`, register state, the stack's return addresses, the module map, the `.boot` IAT and the import descriptor. This is what proved the loader ignored the import table. |
| `winrun.py` | End-to-end native run: answers the offline prompt (Enter) and the title screen (Space), reports the flow, never touches the Vanguard modal. |
| `snap.py` | Primary-screen screenshot via `System.Drawing`. |
| `shot.py` | Launches the game, waits for the FRE splash, screenshots it, leaves the process running. |

## tools/probe/ — Linux side

| file | what it does |
|---|---|
| `run-133.sh` | **The launcher.** Starts the game, answers the offline prompt and title screen, preserves the previous log in `/tmp/Lion-previous.log`, and shuts down cleanly (`wineserver -k`) on exit. |
| `key133.py` | Sends a key through XTEST using only `ctypes` + `libX11`/`libXtst` (no `xdotool`). |
| `setup-vgc.sh` | Installs `vService.exe` as the `vgc` service in the prefix (binary + correctly escaped registry key). Requires `wineserver` stopped. |
| `vgctest.sh` | Launches and reports whether a Vanguard fault modal was queued. |
| `matchtest.sh` | Launches, walks into a battle, watches the level/match log, screenshots the result. |
| `test-install.sh` | Installs a rebuilt exe into the prefix and runs it with `WINEDEBUG=+seh`, summarising exception codes. |
| `fretest.sh`, `press2.sh` | Early keypress experiments (window enumeration, XTEST) that established the offline prompt can be answered with Enter. |
| `shot133.sh` | Launch → wait for the main menu → screenshot with `grim`. |
| `verify133.sh` | Relaunch and report the FRE states (used to show FRE is not persisted). |
| `testrun3.sh` | Timing test for the launcher (FRE → menu, with keypresses). |
| `tail133.sh`, `dc.sh`, `front.sh`, `xcheck.sh`, `svgcdiag.sh`, `logtail.sh` | Small diagnostics: log tails, dynamic-config greps, frontend state, X display availability, service/registry checks. |
| `closewin.py` | Kills orphaned X windows left by killed Wine processes (ignores X protocol errors). |

## Constants you will need

```
OEP                       0x7e698b0
packer IAT                0x8011000
IAT sentinel              0xC01F9CEFB0F443AF
.text RVA / size          0x1000 / 0x800f4bd
.boot RVA / entry         0xbef8000
SizeOfImage               0xbf05000
SIMD level global         0xab7cbf0   (4 = AVX2 on all test machines)
```

## Privileges

Everything on the Windows side that touches the game process requires the Vanguard
service to be **stopped** (`sc.exe stop vgk`, elevated). Only the machine's owner can
do that. Nothing here installs into the game directory except swapping
`Lion-Win64-Shipping.exe` (a `.packed` copy is kept alongside).

# 2XKO 1.3.3 — unpacking a packed UE5 shipping build and running it offline

Field notes and tooling from taking a retail, **packed** `Lion-Win64-Shipping.exe`
(2XKO 1.3.3, UE 5.4.4) apart, rebuilding it as a normal executable, and getting it to
start offline under Proton on Linux.

The result runs: engine init → first-run experience → main menu → **training mode**.

> Everything here is for offline archival use on hardware you own. No game content,
> no game binaries, and no anti-cheat software is included or redistributed.

---

## The three problems, in order

### 1. The exe is packed and will not run under Wine

The shipped `Lion-Win64-Shipping.exe` has `.text` with characteristic `0x20`
(no code/no execute bit), imports exactly one module (`stub.dll`), and extra sections
`.toir` and `.stub`. Under Proton it exits silently after a service-manager RPC.
Unpacking was the only route.

**Solution:** a fault-driven dumper (see `docs/01-unpacking-the-packer.md`).

- decrypt all 32,784 pages of `.text` (134,280,381 bytes)
- find the original entry point: **RVA `0x7e698b0`**
- recover the packer's import table: **RVA `0x8011000`**, 1,214 imports across 36 DLLs
- rebuild a normal exe around that decrypted image

Two non-obvious details:

- The packer flips a page to `RX` **before** it finishes writing the plaintext, so a
  read immediately after the protection change can capture a half-written page. The
  dumper only accepts a page when **two consecutive reads agree** (`stable_read`).
- The packer "tires" after ~1,000–2,500 faults and stops decrypting. The dumper is
  resumable and a pacer relaunches the process when a run of pages refuses.

### 2. Windows ignored the rebuilt import table

First rebuild booted under Wine but died natively with `0xC0000005` at offset `0`
(RIP = 0) and no log.

Diagnosis: the synthesised import directory was **never processed**. Proof: pointing
the descriptor at a DLL that does not exist did not even fail `CreateProcess`, and the
IAT thunks stayed zero, so the bootstrap called address 0.

**Solution:** the bootstrap does not use the PE loader at all
(`docs/02-import-bootstrap.md`). It walks `PEB → Ldr → InLoadOrderModuleList` for the
module whose export name is `KERNEL32`, parses that export table for
`LoadLibraryA`/`GetProcAddress` (verified to be real code, not forwarders, in Windows
`kernel32` and in Wine's `kernel32`/`kernelbase`), fills all 1,214 slots, then jumps to
the OEP. The rebuilt exe has **no import directory**.

### 3. First run and Vanguard

`FREGameModeState::CheckDisconnectedSupport` looked like a deadlock. It was an
unclicked dialog:

> **UNABLE TO ESTABLISH CONNECTION FOR LOGIN.**
> PROCEED IN OFFLINE MODE AS `<account>`?
> **[OK]** ← already focused

One Enter walks `CheckDisconnectedSupport → RequireOnlinePlatform → AttractMode →
Complete → Mode.MainMenu`. FRE re-runs on every launch, and the title screen that
follows needs one "press any button".

Then the main menu raised `VANGUARD ERROR: VAN-83` (single button: EXIT GAME) because
`LogLionVanguard: Initializing Vanguard client.` could not reach Vanguard. The SDK
connects to `\\.\pipe\933823D3-C77B-4BAE-89D7-A92B567236BC`; a stub service answers the
login + heartbeat exchange and Wine's SCM auto-starts it. Details in
`docs/03-first-run-and-vanguard.md`.

---

## Quick start (ThinkPad / Proton)

```bash
~/2XKO/run-133.sh          # launches, answers the offline prompt + title screen
```

One-time prefix setup (already done on the reference machine):

```bash
bash tools/probe/setup-vgc.sh ~/2XKO/vService.exe   # installs the vgc stub service
```

Do not start a second instance while one is running — the launcher shuts down any
existing Wine session first.

## Rebuilding the exe

```bash
cd <workdir>                       # expects textdump/text.bin and dumpimg/imports.json
python tools/rebuild2.py --out unpacked-133.exe
python tools/mkboot.py             # prints the generated stub, disassembled (capstone)
```

`rebuild2.py` expects the default paths `C:\2XKO-unpack\textdump\text.bin` and
`C:\2XKO-unpack\dumpimg\imports.json`; both are outputs of the dumping stage and are
**not** in this repo.

## Repo layout

```
README.md
NOTICE.md
docs/
  01-unpacking-the-packer.md    fault-walking the .text decryption, OEP, IAT
  02-import-bootstrap.md        why the loader was bypassed; the PEB resolver
  03-first-run-and-vanguard.md  FRE prompt, offline mode, the vgc stub service
  04-tooling.md                 what every script does
  05-gotchas.md                 the traps that cost the most time
  06-timeline.md                chronological log of the whole effort
tools/                          the scripts themselves (Python / PowerShell / shell)
```

## Facts worth keeping

| item | value |
|---|---|
| entry point (OEP) | RVA `0x7e698b0` |
| packer IAT | RVA `0x8011000`, 1,214 imports / 36 modules |
| IAT block sentinel | `0xC01F9CEFB0F443AF` |
| `.text` | RVA `0x1000`, 134,280,381 bytes (32,784 pages) |
| bootstrap section | `.boot` at RVA `0xbef8000`, RWX, entry `0xbef8000` |
| rebuilt `SizeOfImage` | `0xbf05000` |
| Vanguard pipe | `\\.\pipe\933823D3-C77B-4BAE-89D7-A92B567236BC` |
| packed exe (reference) | size 195,274,168, sha256 `bf9a7e97…` |
| rebuilt exe | size 195,327,488, sha256 `866f45f2…` |

## Environment notes

- Dumping and native debugging were done on Windows with `vgk` (Vanguard) **stopped**;
  only the machine's owner can start/stop that service.
- Testing was done under Proton Experimental in its own prefix with
  `WINEDLLOVERRIDES=ucrtbase=n,b` (Wine's builtin `ucrtbase` lacks `wcstoumax`).
- The reference Linux machine is an Intel Meteor Lake laptop (no AVX-512); so is the
  Windows box (Zen 3). The dispatcher's SIMD level global at RVA `0xAB7CBF0` reads 4
  ("AVX2") on both.

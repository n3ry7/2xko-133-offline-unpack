# 5. Gotchas

Everything here cost real time. Ordered roughly by how much.

## Packer / dumping

1. **The packer sets a page readable before the plaintext write completes.** Reading on
   the protection flip captures half-written pages. Only accept a page when two
   consecutive reads agree (`stable_read`). Symptom: a dump that boots and then dies on
   "AVX-512" instructions that are really EVEX garbage.
2. **Correctness is only proven against the live process.** The final check was
   `verify.py`: every page the game itself had decrypted matched the dump (2,683 pages,
   0 differ), and the pages the walker produced match the live bytes byte-for-byte.
3. **The packer tires** after ~1,000–2,500 faults; pages then refuse until the process
   is restarted. Hence the resumable bitmap + pacer + relaunch harness.
4. **Private pages stop executing.** The handler/stub must live in an image page
   (found in `libcef.dll` BSS). `VirtualProtectEx` fails with **error 87** on every
   `Lion-Win64-Shipping.exe` page, so "just allocate some space" does not work.
5. **`time.sleep()` on Windows is 1–15 ms.** Busy-wait on `QueryPerformanceCounter`
   when polling for a protection change.
6. **The VEH chain is walked oldest-first**, needs `PEB->CrossProcessFlags` bit 2 to be
   enabled, and the handler pointer returned by `AddVectoredExceptionHandler` is
   **encoded** (`EncodePointer`) — inline it properly or the chain walk corrupts.

## Rebuild / bootstrap

7. **Windows silently ignores import directories it does not like.** No error, no
   module load, IAT stays zero, `call [rip+iat]` → RIP 0. Test with a deliberately
   bogus DLL name: if `CreateProcess` still succeeds, the directory is being skipped.
8. **RVA vs section offset.** `mov [r15+0x740], r10` with `r15 = image base` writes to
   `base+0x740` (the read-only header), not to the section at `0xbef8000`. The fault
   address gives it away (`0x140000740`).
9. **`mod=00` with base `r13`/`rbp` is not "no displacement"** — it means "no base,
   disp32". `mov r10d,[r13+rax*4]` must be encoded with `mod=01, disp8=0`.
10. **`[r15+disp32]` needs no SIB** (`rm=111`). Adding one shifts everything.
11. **Verify generated machine code with a disassembler** before running it. `mkboot.py`
    prints a capstone dump; both of the encoding bugs above were obvious there and
    would have been miserable to debug from a crash.

## First run / Vanguard

12. **FRE is not a deadlock.** The offline prompt has OK focused; one Enter advances it.
    It runs every launch.
13. **`bAutomaticallyDismissFRE` / `bAlwaysShowFREOnLoading` are UPROPERTYs, not cvars.**
    `[ConsoleVariables]` in `Engine.ini` is read (the log proves it) and ignored.
14. **`vService.exe` is a Windows service**, not a console program: run from a shell it
    just exits. It needs the SCM, so register it in the prefix registry and let Wine's
    `services.exe` start it.
15. **Wine `.reg` keys need doubled backslashes.** A single-backslash key is parsed as
    a different key name; the service then never starts and nothing complains loudly.
16. **A single-button modal may be "EXIT GAME".** Never send keys blindly after
    `Mode.MainMenu`; the launcher stops pressing as soon as the menu or a modal appears.

## Host / process hygiene

17. **`pkill -f wine` kills its own shell** — the remote command line contains the word
    `wine`, so it matches itself and the session dies silently (exit 1, no output).
    Use `killall -9 wine …` or a pattern that cannot match the command line.
18. **`zsh` globs bracket patterns.** `pkill -f '[w]ine'` fails with
    "no matches found" before `pkill` even runs. Quote it or avoid brackets.
19. **Killed Wine runs leave orphans**: `EpicWebHelper` (several), `crashpad_handler`,
    `wineserver`. Eleven of them took the machine to **load average 62** and made a
    level load look like a hang. Clean up after test runs.
20. **The debugger freezes the child between events.** A game that "stalls at D3D11
    adapter enumeration" under `dbgrun.py` is fine without the debugger attached.
21. **Screenshot after the process is killed** captures whatever is on screen next
    (usually the terminal), not the game.
22. **X auth changes when the desktop session restarts.** After a logout/login,
    `XOpenDisplay` returns NULL with "Authorization required, but no authorization
    protocol specified" until you are logged back in — the Xwayland instance and its
    cookie are new.
23. **PowerShell strips double quotes** when building native command lines, which
    breaks pipes and patterns passed to `ssh`. Single-quote the whole remote command,
    or pass a script file.

## False leads worth recording

24. **86 "failing" imports** were a working-directory artefact: the validation script
    ran outside the game directory, so `LoadLibraryW("OpenColorIO_2_3.dll")` failed.
    With `Binaries\Win64` on the search path, 36/36 modules and 1,214/1,214 names
    resolve.
25. **`0x40010006` / `0x4001000a` / `0x406d1388`** exceptions in the log are normal
    MSVC C++ exceptions and thread-naming (`SetThreadName`), not faults.

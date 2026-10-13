# open-carl — Extraction SUCCESS (obfuscation defeated)

## What beat the protection
The metadata header is a custom permutation ("version 108") that no static dumper can
read. Instead of cracking it, we used the game's OWN runtime, which has already decoded it:

1. `GameAssembly.dll` exports 244 `il2cpp_*` functions (all 22 enumeration APIs present).
2. Built a `winhttp.dll` proxy (`tools/winhttp_proxy.c`) — UnityPlayer statically imports
   winhttp, so it loads at process init, before the guard runs. It stubs the 4 (network)
   winhttp functions and spawns a thread that walks every assembly/class/method/field via
   the il2cpp exports. The ORIGINAL `CARLProtect.dll` is left intact, so it still decrypts
   the metadata and its integrity check passes (no manifest file is modified; winhttp isn't
   manifested). CARLProtect did NOT block the injection.

## Deliverables (recovered/)
- `runtime-api-dump.cs` — full C# API: 3,540 classes, 23,757 methods, 51 assemblies.
  Game code: Assembly-CSharp.dll (390 classes, e.g. ImpactLab.ActiveHumanoid), Unity.Scripting, __Generated.
- `methods.map` — 23,435 method RVAs (name -> GameAssembly.dll offset); 8,279 are game code.
- `global-metadata.decrypted.dat` — the decrypted (but permuted-header) metadata.

## In progress
- Ghidra headless (`tools/ghidra_scripts/apply_names.py`): import GameAssembly.dll, auto-analyze,
  apply the 23k names at their RVAs, decompile game-code bodies -> recovered/decompiled/game_decompiled.c
  Log: /tmp/ghidra.log. ~30-60 min.

## Modding harness
The winhttp.dll injector is also the harness for adding custom code ("the flash"): it already
runs in-process with full il2cpp access. Next: implement the chosen flash and (optionally)
hook/patch game methods.

## Housekeeping
- ptrace_scope was set to 0 for the memory dump; the runtime route does NOT need it.
  Restore with: echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope
- game-modded/ is a full working copy; original build in Downloads is untouched.
  game-modded/CARLProtect.original.dll backs up the stock guard.

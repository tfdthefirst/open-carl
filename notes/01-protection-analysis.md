# open-carl — Protection Analysis (Project C.A.R.L. 0.8.71 DEV)

Target: Unity **6000.6.1f1** (Unity 6.1), IL2CPP backend, Windows build run via DW-Proton.
Goal: recover a readable, modifiable code tree ("open sesame") into `~/Games/open-carl`.

## Build layout (inputs/game -> the Downloads build)
- `CARL.exe` — Unity bootstrap. Imports `CARLProtect.dll`, calls export `CARLProtect_Init`, then hands off to `UnityPlayer.dll`.
- `CARLProtect.dll` — anti-tamper guard. Single export: `CARLProtect_Init`.
- `GameAssembly.dll` (15 MB) — all game C# compiled via IL2CPP (C# -> C++ -> native).
- `CARL_Data/il2cpp_data/Metadata/global-metadata.dat` (3.4 MB) — the type-system metadata.

## Anti-tamper guard (CARLProtect)
Two independent trust layers, enforced at launch; failure => message
"Project C.A.R.L. has detected that the game is being modified or debugged." then ExitProcess.
Guard logs `CARLPROTECT guard event 0x%03X`.

1. **Manifest layer** — `CARL_Data/official.manifest` lists SHA-256 + size for 25 files;
   `CARL_Data/official.sig` is a 384-byte (**RSA-3072**) signature over the manifest.
2. **Authenticode layer** — PEs signed by a **self-signed RSA-2048** cert
   `CN = Project C.A.R.L. (self-signed)`; verified via `WinVerifyTrust` + `CryptCATAdmin*`.
   (Cert embedded in CARLProtect.dll PE security dir at file offset 0x30c00, 1448 bytes.)

The two keypairs are distinct (2048 vs 3072) and neither private key ships in the build.
Since CARL.exe loads CARLProtect.dll via normal import (no self-Authenticode check on
LoadLibrary), neutralizing `CARLProtect_Init` is viable. Guard editing is in-scope per CTF rules.

## The real lock: encrypted metadata
`global-metadata.dat` is **fully encrypted**:
- Shannon entropy **8.000 bits/byte**, zero-byte fraction **0.004**, **no readable identifiers**.
- Header magic `0xFAB11BAF` left in clear as a decoy; declared version reads **108**
  (real Unity 6.1 IL2CPP metadata version is **31**) — i.e. the version field is ciphertext too.
- All post-magic header offsets are garbage (e.g. 0xFB7C99F8), confirming encryption not reshuffle.

=> Static Il2CppDumper cannot parse it until decrypted.

## Recovery plan
- **Route A (dynamic):** neutralize guard -> run -> IL2CPP runtime decrypts metadata into RAM ->
  dump from `/proc/<pid>/mem` -> feed plaintext to Il2CppDumper/Inspector + GameAssembly.dll.
- **Route B (static):** reverse the metadata decryptor in GameAssembly.dll
  (il2cpp MetadataLoader hook), recover key+algo, decrypt offline. Bonus: you own the key.

Output: `recovered/DummyDll` (C# API skeleton), `recovered/cpp` (Ghidra symbol map / decompiled
bodies), then a BepInEx IL2CPP harness in `mods/` to add custom content and run it guard-free.

# open-carl — Metadata extraction findings (Route A progress)

## Done
- Toolchain installed (no root): .NET 8 runtime + Il2CppDumper v6.7.46 in `tools/`.
- **Decrypted metadata recovered from RAM.** A clean, unmodified run decrypts
  `global-metadata.dat` into anonymous heap in the game process (reparented to init,
  needs ptrace_scope=0 to read). Dumped 3,431,886 bytes -> `recovered/global-metadata.decrypted.dat`.
  Entropy dropped 8.0 -> ~5; 46,930 readable strings incl. real game text
  ("SELECT ANOTHER CARL", "SPINAL CORD", ...). Route A decryption = SOLVED.

## Blocker: custom-permuted metadata header ("version 108")
- `GameAssembly.dll` was rebuilt with a **reordered Il2CppGlobalMetadataHeader struct**
  and the sanity magic 0xFAB11BAF stripped from the binary (0 occurrences).
- Only ONE metadata copy in RAM (permuted, declared version 108). No canonical v31 copy.
- Confirmed partial permutation:
  - `stringLiteralData` is at its canonical slot (ints[4,5] = off 7094, size 28876 — contains literal text).
  - The identifier `string` section is really at **off 178468 / size 618413**, but that value is
    stored in the header's canonical `events` slot (ints[8,9]). So fields are shuffled, no simple pattern.
- Il2CppDumper (forced v31) reads early sections then dies at
  `fieldDefaultValues.ToDictionary(fieldIndex)` (dup key 0x200A0000) because the shuffled
  header feeds it the wrong offset.

## Two ways to finish
### Option R-A: Static header crack (the "trophy", Route B)
Open `GameAssembly.dll` in Ghidra, find the IL2CPP metadata accessors
(e.g. GetStringFromIndex => reveals byte-offset of each header field), recover the full
permutation, rewrite a canonical v31 header, re-run Il2CppDumper -> DummyDll + script.json
+ method RVAs for Ghidra. Needs Ghidra+JDK (~600 MB). Deterministic; heavy.

### Option R-B: Runtime API extraction + modding harness (recommended)
Install BepInEx (IL2CPP) / Il2CppInterop. The game's own runtime already parsed the
permuted metadata, so Il2CppInterop generates complete C# proxy assemblies (every
namespace/type/method/field signature) by calling il2cpp APIs in-process -- bypassing the
header puzzle entirely -- and simultaneously gives the harness to ADD custom code ("the
flash"). Needs BepInEx IL2CPP (~30 MB) and defeating/neutralizing CARLProtect at launch
(in scope). Fast; also delivers the modding goal.

Recommendation: R-B for the complete goal (read + modify + add), with R-A later as the
pure-offline trophy.

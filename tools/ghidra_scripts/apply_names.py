# Ghidra headless post-script: name functions from methods.map, then decompile game code.
# @category CARL
import os, re
from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

MAP = os.environ.get("MAPFILE", "/home/battledoge/Games/open-carl/recovered/methods.map")
OUT = os.environ.get("DECOMP_OUT", "/home/battledoge/Games/open-carl/recovered/decompiled")
# namespaces considered "game code" (decompile these bodies)
GAME_PREFIXES = ("ImpactLab", "Carl", "__Generated", "Unity.Scripting")

def sanitize(n):
    n = n.replace("::", "__").replace(".", "_")
    n = re.sub(r"[^A-Za-z0-9_]", "_", n)
    return n[:200]

fm = currentProgram.getFunctionManager()
base = currentProgram.getImageBase()
listing = currentProgram.getListing()

entries = []
with open(MAP) as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        rva_s, name = parts
        try:
            rva = int(rva_s, 16)
        except ValueError:
            continue
        entries.append((rva, name))

print("loaded %d map entries" % len(entries))

named = 0
created = 0
addr_name = {}
for rva, name in entries:
    addr = base.add(rva)
    addr_name[addr] = name
    func = fm.getFunctionAt(addr)
    if func is None:
        try:
            func = createFunction(addr, None)
            if func is not None:
                created += 1
        except Exception:
            func = None
    if func is not None:
        try:
            func.setName(sanitize(name), SourceType.USER_DEFINED)
            named += 1
        except Exception:
            pass

print("named=%d created=%d" % (named, created))

# ---- decompile game-code functions ----
try:
    os.makedirs(OUT)
except Exception:
    pass
di = DecompInterface()
di.openProgram(currentProgram)
mon = ConsoleTaskMonitor()

game = [(rva, name) for (rva, name) in entries if name.startswith(GAME_PREFIXES)]
print("decompiling %d game-code functions..." % len(game))
outf = open(os.path.join(OUT, "game_decompiled.c"), "w")
outf.write("// Project C.A.R.L. decompiled game code (Ghidra via runtime RVAs)\n\n")
done = 0
for rva, name in game:
    addr = base.add(rva)
    func = fm.getFunctionAt(addr)
    if func is None:
        continue
    try:
        res = di.decompileFunction(func, 60, mon)
        if res is not None and res.decompileCompleted():
            outf.write("// ==== %s  @0x%x ====\n" % (name, rva))
            outf.write(res.getDecompiledFunction().getC())
            outf.write("\n\n")
            done += 1
            if done % 500 == 0:
                outf.flush()
                print("  decompiled %d/%d" % (done, len(game)))
    except Exception as e:
        pass
outf.close()
print("DECOMPILE DONE: %d functions -> %s/game_decompiled.c" % (done, OUT))

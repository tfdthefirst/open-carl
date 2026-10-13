#!/usr/bin/env python3
"""Dump decrypted IL2CPP global-metadata from the running CARL game.

Works once ptrace is permitted (ptrace_scope=0, OR run this under sudo).
Finds the CARL.exe process that mapped GameAssembly.dll, searches its anonymous
memory for the metadata magic, and validates the candidate is genuine plaintext
(entropy < 6.5 and contains b"Assembly-CSharp") before saving.

Usage:
  python3 dump_metadata_final.py           # auto-find pid
  python3 dump_metadata_final.py <pid>     # explicit pid
"""
import os, sys, glob, struct, math, collections

METADATA_SIZE = 3431886
MAGIC = b"\xaf\x1b\xb1\xfa"
OUT = "/home/battledoge/Games/open-carl/recovered/global-metadata.decrypted.dat"

def entropy(b):
    if not b: return 0.0
    c = collections.Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def find_game_pid():
    cand = []
    for c in glob.glob("/proc/[0-9]*/cmdline"):
        try:
            if b"CARL.exe" not in open(c, "rb").read():
                continue
        except Exception:
            continue
        pid = int(c.split("/")[2])
        try:
            if any("GameAssembly.dll" in l for l in open(f"/proc/{pid}/maps")):
                cand.append(pid)
        except Exception:
            pass
    return cand

def dump(pid):
    mem = open(f"/proc/{pid}/mem", "rb", buffering=0)
    for l in open(f"/proc/{pid}/maps"):
        p = l.split()
        if p[1][0] != "r":
            continue
        a, b = p[0].split("-"); s, e = int(a, 16), int(b, 16)
        if e - s < METADATA_SIZE:
            continue
        pos = s; carry = b""; cpos = s
        while pos < e:
            n = min(16*1024*1024, e - pos)
            try:
                mem.seek(pos); data = mem.read(n)
            except Exception:
                break
            if not data:
                break
            buf = carry + data
            off = buf.find(MAGIC)
            while off != -1:
                hit = cpos + off
                try:
                    mem.seek(hit); blob = mem.read(METADATA_SIZE)
                except Exception:
                    blob = None
                if blob and len(blob) == METADATA_SIZE:
                    ver = struct.unpack_from("<i", blob, 4)[0]
                    if entropy(blob) < 6.5 and b"Assembly-CSharp" in blob:
                        return blob, hit, ver
                off = buf.find(MAGIC, off + 1)
            carry = buf[-4:]; cpos = pos + n - len(carry); pos += n
    return None, None, None

def main():
    pids = [int(sys.argv[1])] if len(sys.argv) > 1 else find_game_pid()
    if not pids:
        print("[-] no CARL.exe process with GameAssembly.dll mapped (is the game running?)")
        sys.exit(2)
    print("[*] target pid(s):", pids)
    for pid in pids:
        try:
            blob, hit, ver = dump(pid)
        except PermissionError:
            print(f"[-] pid {pid}: permission denied — set ptrace_scope=0 or run with sudo")
            continue
        if blob:
            os.makedirs(os.path.dirname(OUT), exist_ok=True)
            open(OUT, "wb").write(blob)
            print(f"[+] pid {pid}: metadata @0x{hit:x}  real version={ver}")
            print(f"[+] wrote {len(blob)} bytes -> {OUT}  entropy={entropy(blob):.3f}")
            return
    print("[-] metadata not found in target process memory")
    sys.exit(1)

if __name__ == "__main__":
    main()

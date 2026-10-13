#!/usr/bin/env python3
"""Scan a running (Wine/Proton) process for decrypted IL2CPP global-metadata and dump it.

Looks for the plaintext header signature: magic 0xFAB11BAF followed by version 31,
then writes METADATA_SIZE bytes (the original encrypted file's length) starting there.
"""
import sys, os, re, struct, glob

METADATA_SIZE = 3431886          # byte length of the on-disk global-metadata.dat
SIG = bytes.fromhex("af1bb1fa") + struct.pack("<i", 31)   # magic + version 31
OUT = "/home/battledoge/Games/open-carl/recovered/global-metadata.decrypted.dat"

def find_pids():
    pids = []
    for p in glob.glob("/proc/[0-9]*/comm"):
        try:
            comm = open(p).read().strip()
        except Exception:
            continue
        if "CARL" in comm:
            pids.append((int(p.split("/")[2]), comm))
    # also match via cmdline (wine passes full path)
    for p in glob.glob("/proc/[0-9]*/cmdline"):
        try:
            cmd = open(p,"rb").read().replace(b"\0",b" ").decode("latin1")
        except Exception:
            continue
        if "CARL.exe" in cmd:
            pid = int(p.split("/")[2])
            if pid not in [x[0] for x in pids]:
                pids.append((pid, "cmdline:CARL.exe"))
    return pids

def readable_regions(pid):
    regs = []
    for line in open(f"/proc/{pid}/maps"):
        parts = line.split()
        addrs, perms = parts[0], parts[1]
        if "r" not in perms:            # need read
            continue
        if perms[3] == "s":             # skip shared file maps? keep private; metadata is private rw
            pass
        a, b = addrs.split("-")
        start, end = int(a,16), int(b,16)
        size = end - start
        if size < METADATA_SIZE:        # buffer must fit
            continue
        regs.append((start, end, perms, parts[-1] if len(parts)>5 else ""))
    return regs

def scan(pid):
    mem = open(f"/proc/{pid}/mem","rb", buffering=0)
    for start, end, perms, path in readable_regions(pid):
        pos = start
        CHUNK = 8*1024*1024
        carry = b""
        carry_pos = start
        while pos < end:
            n = min(CHUNK, end-pos)
            try:
                mem.seek(pos); data = mem.read(n)
            except Exception:
                break
            if not data:
                break
            buf = carry + data
            i = buf.find(SIG)
            if i != -1:
                hit = carry_pos + i
                print(f"[+] pid {pid}: signature at 0x{hit:x} in region {perms} {path}")
                try:
                    mem.seek(hit); blob = mem.read(METADATA_SIZE)
                except Exception as e:
                    print("    read failed:", e);
                    blob=None
                if blob and len(blob)==METADATA_SIZE:
                    return blob, hit, perms, path
            carry = buf[-len(SIG):]
            carry_pos = pos + n - len(carry)
            pos += n
    return None, None, None, None

def entropy(b):
    import math, collections
    if not b: return 0
    c=collections.Counter(b); n=len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def main():
    pids = find_pids()
    if len(sys.argv) > 1:
        pids = [(int(sys.argv[1]), "argv")]
    if not pids:
        print("[-] no CARL process found"); sys.exit(2)
    print("[*] candidate pids:", pids)
    for pid, how in pids:
        print(f"[*] scanning pid {pid} ({how}) ...")
        blob, addr, perms, path = scan(pid)
        if blob:
            os.makedirs(os.path.dirname(OUT), exist_ok=True)
            open(OUT,"wb").write(blob)
            H = entropy(blob)
            print(f"[+] dumped {len(blob)} bytes -> {OUT}")
            print(f"    entropy={H:.3f} bits/byte (expect ~4-5 for plaintext metadata)")
            import subprocess
            ids = subprocess.run(["bash","-c",
                f"strings -n6 {OUT} | grep -aiE 'UnityEngine|Assembly-CSharp|CARL|System\\.' | head -8"],
                capture_output=True, text=True).stdout
            print("    sample identifiers:\n"+ "\n".join("      "+l for l in ids.splitlines()))
            return
    print("[-] signature not found in any candidate process (metadata may not be loaded yet)")
    sys.exit(1)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Launch Project C.A.R.L. (clean, windowed) and dump decrypted IL2CPP metadata from RAM.

ptrace_scope=1, so this process launches the game itself (ancestor => allowed to read
descendant /proc/<pid>/mem). We run the UNMODIFIED game so CARLProtect passes; reading
/proc/pid/mem does not set TracerPid, so the anti-debug guard stays quiet.
"""
import os, sys, time, struct, glob, subprocess, signal, collections, math

GAME = "/home/battledoge/Downloads/Project C.A.R.L. 0.8.71 DEV Windows"
PROTON = "/home/battledoge/.local/share/lutris/runners/wine/dw-proton-x86_64/proton"
COMPAT = "/home/battledoge/Games/carl-proton"
METADATA_SIZE = 3431886
SIG = bytes.fromhex("af1bb1fa") + struct.pack("<i", 31)
OUT = "/home/battledoge/Games/open-carl/recovered/global-metadata.decrypted.dat"
TIMEOUT = 90

def env():
    e = dict(os.environ)
    e.update(UMU_ID="0", SteamAppId="0", SteamGameId="0",
             STEAM_COMPAT_DATA_PATH=COMPAT, STEAM_COMPAT_CLIENT_INSTALL_PATH=COMPAT,
             DXVK_FRAME_RATE="30", DXVK_LOG_LEVEL="none", VKD3D_DEBUG="none",
             PROTON_ENABLE_WAYLAND="1")
    return e

def carl_pids():
    pids = []
    for c in glob.glob("/proc/[0-9]*/cmdline"):
        try:
            cmd = open(c, "rb").read()
        except Exception:
            continue
        if b"CARL.exe" in cmd:
            pids.append(int(c.split("/")[2]))
    return pids

def entropy(b):
    if not b: return 0
    c = collections.Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def scan_pid(pid):
    try:
        mem = open(f"/proc/{pid}/mem", "rb", buffering=0)
    except Exception as e:
        return None, None
    for line in open(f"/proc/{pid}/maps"):
        parts = line.split()
        perms = parts[1]
        if perms[0] != "r":
            continue
        a, b = parts[0].split("-")
        start, end = int(a, 16), int(b, 16)
        if end - start < METADATA_SIZE:
            continue
        pos = start; carry = b""; cpos = start
        while pos < end:
            n = min(8*1024*1024, end - pos)
            try:
                mem.seek(pos); data = mem.read(n)
            except Exception:
                break
            if not data:
                break
            buf = carry + data
            i = buf.find(SIG)
            if i != -1:
                hit = cpos + i
                try:
                    mem.seek(hit); blob = mem.read(METADATA_SIZE)
                except Exception:
                    blob = None
                if blob and len(blob) == METADATA_SIZE and entropy(blob) < 6.5:
                    return blob, hit
            carry = buf[-len(SIG):]
            cpos = pos + n - len(carry)
            pos += n
    return None, None

def main():
    cmd = [PROTON, "waitforexitandrun", f"{GAME}/CARL.exe",
           "-screen-fullscreen", "0", "-screen-width", "640", "-screen-height", "480",
           "-force-d3d11"]
    print("[*] launching game (windowed 640x480)...")
    proc = subprocess.Popen(cmd, cwd=GAME, env=env(),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            preexec_fn=os.setsid)
    start = time.time()
    found = None
    try:
        while time.time() - start < TIMEOUT:
            time.sleep(1.0)
            for pid in carl_pids():
                blob, hit = scan_pid(pid)
                if blob:
                    os.makedirs(os.path.dirname(OUT), exist_ok=True)
                    open(OUT, "wb").write(blob)
                    print(f"[+] pid {pid}: decrypted metadata at 0x{hit:x}")
                    print(f"[+] wrote {len(blob)} bytes -> {OUT}  (entropy {entropy(blob):.3f})")
                    found = True
                    break
            if found:
                break
            else:
                el = int(time.time()-start)
                if el % 5 == 0:
                    print(f"    ... {el}s, pids={carl_pids()}")
    finally:
        print("[*] terminating game...")
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            pass
        time.sleep(2)
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass
        subprocess.run(["pkill", "-9", "-f", "CARL.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not found:
        print("[-] metadata signature not found within timeout")
        sys.exit(1)
    # quick readable-identifier proof
    out = subprocess.run(["bash","-c",
        f"strings -n6 {OUT} | grep -aiE 'UnityEngine|Assembly-CSharp|CARL|System\\.' | head -10"],
        capture_output=True, text=True).stdout
    print("[+] sample identifiers now readable:")
    print("\n".join("      "+l for l in out.splitlines()))

if __name__ == "__main__":
    main()

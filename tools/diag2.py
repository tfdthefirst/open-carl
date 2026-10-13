#!/usr/bin/env python3
import os, time, glob, subprocess, signal

GAME="/home/battledoge/Downloads/Project C.A.R.L. 0.8.71 DEV Windows"
PROTON="/home/battledoge/.local/share/lutris/runners/wine/dw-proton-x86_64/proton"
COMPAT="/home/battledoge/Games/carl-proton"
MAGIC=b"\xaf\x1b\xb1\xfa"

def env():
    e=dict(os.environ)
    e.update(UMU_ID="0",SteamAppId="0",SteamGameId="0",STEAM_COMPAT_DATA_PATH=COMPAT,
             STEAM_COMPAT_CLIENT_INSTALL_PATH=COMPAT,DXVK_LOG_LEVEL="none",
             VKD3D_DEBUG="none",PROTON_ENABLE_WAYLAND="1")
    return e

def carl_pids():
    out=[]
    for c in glob.glob("/proc/[0-9]*/cmdline"):
        try: cmd=open(c,"rb").read()
        except: continue
        if b"CARL.exe" in cmd: out.append(int(c.split("/")[2]))
    return out

def ppid(pid):
    try:
        for l in open(f"/proc/{pid}/status"):
            if l.startswith("PPid:"): return l.split()[1]
    except: pass
    return "?"

def count_magic(pid):
    """Return total MAGIC occurrences across readable regions, or an error string."""
    try:
        m=open(f"/proc/{pid}/mem","rb",buffering=0)
    except Exception as e:
        return f"NO({e.__class__.__name__})"
    total=0
    for l in open(f"/proc/{pid}/maps"):
        p=l.split()
        if p[1][0]!="r": continue
        a,b=p[0].split("-"); s,e=int(a,16),int(b,16)
        if e-s < 3431886 or e-s > 800*1024*1024: continue
        pos=s; carry=b""
        while pos<e:
            n=min(16*1024*1024,e-pos)
            try:
                m.seek(pos); d=m.read(n)
            except Exception:
                break
            if not d: break
            total += (carry+d).count(MAGIC)
            carry=(carry+d)[-4:]
            pos+=n
    return total

def info(pid):
    has_ga=has_meta=False
    try:
        for l in open(f"/proc/{pid}/maps"):
            if "GameAssembly.dll" in l: has_ga=True
            if "global-metadata" in l: has_meta=True
    except Exception as e:
        return f"pid {pid}: maps unreadable ({e})"
    mag=count_magic(pid)
    return (f"pid {pid}: ppid={ppid(pid)} GameAssembly={has_ga} "
            f"metadata_mapped={has_meta} magic_or_memstatus={mag}")

def main():
    cmd=[PROTON,"waitforexitandrun",f"{GAME}/CARL.exe","-screen-fullscreen","0",
         "-screen-width","640","-screen-height","480","-force-d3d11"]
    print("[*] launching...")
    proc=subprocess.Popen(cmd,cwd=GAME,env=env(),stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL,preexec_fn=os.setsid)
    try:
        for wait in (25,20,25):
            time.sleep(wait)
            print(f"\n===== snapshot  pids={carl_pids()} =====")
            for pid in carl_pids():
                print("  "+info(pid))
    finally:
        try: os.killpg(os.getpgid(proc.pid),signal.SIGTERM)
        except: pass
        time.sleep(2)
        subprocess.run(["pkill","-9","-f","CARL.exe"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

if __name__=="__main__":
    main()

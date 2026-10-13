#!/usr/bin/env python3
import os, sys, time, struct, glob, subprocess, signal

GAME = "/home/battledoge/Downloads/Project C.A.R.L. 0.8.71 DEV Windows"
PROTON = "/home/battledoge/.local/share/lutris/runners/wine/dw-proton-x86_64/proton"
COMPAT = "/home/battledoge/Games/carl-proton"
MAGIC = b"\xaf\x1b\xb1\xfa"
NEEDLES = [b"Assembly-CSharp", b"UnityEngine.CoreModule", b"CARLProtect", b"<Module>"]

def env():
    e = dict(os.environ)
    e.update(UMU_ID="0", SteamAppId="0", SteamGameId="0",
             STEAM_COMPAT_DATA_PATH=COMPAT, STEAM_COMPAT_CLIENT_INSTALL_PATH=COMPAT,
             DXVK_LOG_LEVEL="none", VKD3D_DEBUG="none", PROTON_ENABLE_WAYLAND="1")
    return e

def carl_pids():
    out=[]
    for c in glob.glob("/proc/[0-9]*/cmdline"):
        try: cmd=open(c,"rb").read()
        except: continue
        if b"CARL.exe" in cmd: out.append(int(c.split("/")[2]))
    return out

def diag(pid, report):
    try:
        mem=open(f"/proc/{pid}/mem","rb",buffering=0)
    except Exception as e:
        report.append(f"pid {pid}: OPEN FAILED {e}"); return False
    readable=0; denied=0; magichits=[]; needlehits={}
    for line in open(f"/proc/{pid}/maps"):
        p=line.split(); perms=p[1]
        if perms[0]!="r": continue
        a,b=p[0].split("-"); s,e=int(a,16),int(b,16)
        sz=e-s
        pos=s; carry=b""; cpos=s; ok=False
        while pos<e:
            n=min(16*1024*1024,e-pos)
            try:
                mem.seek(pos); data=mem.read(n); ok=True
            except Exception:
                denied+=1; break
            if not data: break
            buf=carry+data
            off=buf.find(MAGIC)
            while off!=-1 and len(magichits)<12:
                addr=cpos+off
                ctx=buf[off:off+8].hex()
                magichits.append((addr,ctx,perms,p[-1] if len(p)>5 else ""))
                off=buf.find(MAGIC,off+1)
            for nd in NEEDLES:
                if nd in buf and nd not in needlehits:
                    needlehits[nd]=(cpos+buf.find(nd),perms,p[-1] if len(p)>5 else "")
            carry=buf[-32:]; cpos=pos+n-len(carry); pos+=n
        if ok: readable+=1
    report.append(f"pid {pid}: readable_regions={readable} denied_regions={denied}")
    for a,ctx,perms,path in magichits:
        report.append(f"   MAGIC @0x{a:x} bytes={ctx} {perms} {path}")
    for nd,(a,perms,path) in needlehits.items():
        report.append(f"   {nd.decode():22} @0x{a:x} {perms} {path}")
    return bool(magichits or needlehits)

def main():
    cmd=[PROTON,"waitforexitandrun",f"{GAME}/CARL.exe",
         "-screen-fullscreen","0","-screen-width","640","-screen-height","480","-force-d3d11"]
    print("[*] launching...")
    proc=subprocess.Popen(cmd,cwd=GAME,env=env(),stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL,preexec_fn=os.setsid)
    hit=False
    try:
        for t in range(18):          # ~ up to 90s, probe every 5s
            time.sleep(5)
            pids=carl_pids()
            report=[f"--- t={ (t+1)*5 }s pids={pids} ---"]
            any_hit=False
            for pid in pids:
                if diag(pid,report): any_hit=True
            print("\n".join(report))
            if any_hit:
                hit=True; break
    finally:
        try: os.killpg(os.getpgid(proc.pid),signal.SIGTERM)
        except: pass
        time.sleep(2)
        subprocess.run(["pkill","-9","-f","CARL.exe"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    print("[done] hit=",hit)

if __name__=="__main__":
    main()

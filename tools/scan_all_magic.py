#!/usr/bin/env python3
"""Launch game; enumerate ALL 0xFAB11BAF occurrences in its memory and classify each."""
import os, time, struct, glob, subprocess, signal, math, collections

GAME="/home/battledoge/Downloads/Project C.A.R.L. 0.8.71 DEV Windows"
PROTON="/home/battledoge/.local/share/lutris/runners/wine/dw-proton-x86_64/proton"
COMPAT="/home/battledoge/Games/carl-proton"
MAGIC=b"\xaf\x1b\xb1\xfa"
SIZE=3431886

def env():
    e=dict(os.environ)
    e.update(UMU_ID="0",SteamAppId="0",SteamGameId="0",STEAM_COMPAT_DATA_PATH=COMPAT,
             STEAM_COMPAT_CLIENT_INSTALL_PATH=COMPAT,DXVK_LOG_LEVEL="none",
             VKD3D_DEBUG="none",PROTON_ENABLE_WAYLAND="1")
    return e

def game_pid():
    for c in glob.glob("/proc/[0-9]*/cmdline"):
        try:
            if b"CARL.exe" not in open(c,"rb").read(): continue
        except: continue
        pid=int(c.split("/")[2])
        try:
            if any("GameAssembly.dll" in l for l in open(f"/proc/{pid}/maps")): return pid
        except: pass
    return None

def ent(x):
    if not x: return 0
    c=collections.Counter(x); n=len(x)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def classify(blob):
    """Return (version, looks_canonical, has_text, note)."""
    ver=struct.unpack_from("<i",blob,4)[0]
    # canonical v31: ints[4]=stringLiteralDataOffset, ints[5]=size ; that region holds UTF8 literal text
    try:
        sldOff,sldSize=struct.unpack_from("<ii",blob,16)
        canon_text=False
        if 0<sldOff<SIZE and 0<sldSize<SIZE and sldOff+sldSize<=SIZE:
            seg=blob[sldOff:sldOff+sldSize]
            canon_text = b"SELECT ANOTHER CARL" in seg or b"SPINAL CORD" in seg
    except: canon_text=False
    has_text = b"Assembly-CSharp" in blob
    return ver, canon_text, has_text

def scan(pid):
    mem=open(f"/proc/{pid}/mem","rb",buffering=0)
    results=[]
    seen=set()
    for l in open(f"/proc/{pid}/maps"):
        p=l.split()
        if p[1][0]!="r": continue
        a,b=p[0].split("-"); s,e=int(a,16),int(b,16)
        pos=s; carry=b""; cpos=s
        while pos<e:
            n=min(16*1024*1024,e-pos)
            try: mem.seek(pos); d=mem.read(n)
            except: break
            if not d: break
            buf=carry+d; off=buf.find(MAGIC)
            while off!=-1:
                addr=cpos+off
                if addr not in seen and addr+SIZE< e+16*1024*1024:
                    seen.add(addr)
                    try:
                        mem.seek(addr); blob=mem.read(SIZE)
                    except: blob=None
                    if blob and len(blob)==SIZE:
                        ver,canon_text,has_text=classify(blob)
                        H=ent(blob[:65536])
                        results.append((addr,ver,canon_text,has_text,H,blob))
                off=buf.find(MAGIC,off+1)
            carry=buf[-4:]; cpos=pos+n-len(carry); pos+=n
    return results

def main():
    cmd=[PROTON,"waitforexitandrun",f"{GAME}/CARL.exe","-screen-fullscreen","0",
         "-screen-width","640","-screen-height","480","-force-d3d11"]
    print("[*] launching...")
    proc=subprocess.Popen(cmd,cwd=GAME,env=env(),stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL,preexec_fn=os.setsid)
    try:
        saved=False
        for _ in range(25):
            time.sleep(3)
            pid=game_pid()
            if not pid: continue
            res=scan(pid)
            if res:
                print(f"[+] pid {pid}: {len(res)} magic occurrence(s)")
                for addr,ver,ct,ht,H,blob in res:
                    print(f"    @0x{addr:x} version={ver:<6} canon_text={ct} has_'Assembly-CSharp'={ht} hdr_entropy={H:.2f}")
                # save any canonical (version 31 OR canon_text True)
                for addr,ver,ct,ht,H,blob in res:
                    if ver==31 or ct:
                        out=f"/home/battledoge/Games/open-carl/recovered/metadata.canonical.0x{addr:x}.dat"
                        open(out,"wb").write(blob); saved=True
                        print(f"    --> saved canonical candidate: {out}")
                if res: break
        if not saved:
            print("[i] no canonical (v31/canon_text) copy seen; only the permuted v108 buffer exists in RAM")
    finally:
        try: os.killpg(os.getpgid(proc.pid),signal.SIGTERM)
        except: pass
        time.sleep(2)
        subprocess.run(["pkill","-9","-f","CARL.exe"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

if __name__=="__main__":
    main()

/* winhttp.dll flash injector for Project C.A.R.L. (authorized CTF, user-owned build).
 * Replaces the main-menu logo IMAGE with a text image reading "OPEN C.A.R.L." by
 * swapping the LabHUD.logo Texture2D's pixels via ImageConversion.LoadImage at runtime.
 * Original CARLProtect.dll left intact (decrypts metadata, integrity passes).
 * Build: x86_64-w64-mingw32-gcc -shared -O2 -o winhttp.dll winhttp_flash.c -lkernel32
 */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <intrin.h>

static void dlog(const char* m){
    FILE* f=fopen("open-carl-ver.log","a"); if(f){ fputs(m,f); fputc('\n',f); fclose(f);} }
static void dlogp(const char* m, void* p){
    FILE* f=fopen("open-carl-ver.log","a"); if(f){ fprintf(f,"%s %p\n",m,p); fclose(f);} }

/* Hide this module from loader-list enumeration so the game's managed
 * OfficialContent "files loaded from the game folder" check sees only the 25
 * official files. (Authorized CTF; user owns the build and OK'd defeating the guard.) */
typedef struct _LH { struct _LH *F, *B; } LH;
typedef struct _LDRENT {
    LH InLoad; LH InMem; LH InInit; void* DllBase;
} LDRENT;
static void hide_module(void* self){
    char* peb = (char*)__readgsqword(0x60);
    char* ldr = *(char**)(peb + 0x18);           /* PEB->Ldr */
    LH* head = (LH*)(ldr + 0x10);                 /* InLoadOrderModuleList */
    for (LH* cur = head->F; cur != head; cur = cur->F) {
        LDRENT* e = (LDRENT*)cur;                 /* InLoad at offset 0 */
        if (e->DllBase == self) {
            /* Unlink ONLY from InLoadOrderModuleList — that's what
             * EnumProcessModules/Toolhelp (and thus the managed OfficialContent
             * scan) read. Leave InMemoryOrder intact: the loader walks it for
             * address->module lookups during thread creation, so corrupting it
             * crashes the process the moment any thread is spawned. */
            if (e->InLoad.F && e->InLoad.B) { e->InLoad.B->F = e->InLoad.F; e->InLoad.F->B = e->InLoad.B; }
            break;
        }
    }
}

#define ARRAY_DATA_OFF 0x20     /* Il2CppArray vector offset (x64) */
#define LOGO_FIELD_OFF 0xe8     /* LabHUD.logo (UnityEngine.Texture2D) */
#define PNG_PATH "Z:\\home\\battledoge\\Games\\open-carl\\tools\\open-carl-title.png"

typedef void*  (*t_domain_get)(void);
typedef void*  (*t_thread_attach)(void*);
typedef void** (*t_domain_get_assemblies)(void*, size_t*);
typedef void*  (*t_assembly_get_image)(void*);
typedef const char* (*t_image_get_name)(void*);
typedef void*  (*t_class_from_name)(void*, const char*, const char*);
typedef void*  (*t_class_get_type)(void*);
typedef void*  (*t_type_get_object)(void*);
typedef void*  (*t_class_get_method_from_name)(void*, const char*, int);
typedef void*  (*t_class_get_methods)(void*, void**);
typedef const char* (*t_method_get_name)(void*);
typedef uint32_t (*t_method_get_param_count)(void*);
typedef void*  (*t_method_get_param)(void*, uint32_t);
typedef char*  (*t_type_get_name)(void*);
typedef void   (*t_free)(void*);
typedef void*  (*t_array_new)(void*, uintptr_t);
typedef uintptr_t (*t_array_length)(void*);
typedef void*  (*t_runtime_invoke)(void*, void*, void**, void**);
typedef uint32_t (*t_gchandle_new)(void*, int);

static t_domain_get A_domain_get; static t_thread_attach A_thread_attach;
static t_domain_get_assemblies A_dga; static t_assembly_get_image A_agi;
static t_image_get_name A_ign; static t_class_from_name A_cfn;
static t_class_get_type A_cgt; static t_type_get_object A_tgo;
static t_class_get_method_from_name A_cgmfn; static t_class_get_methods A_cgm;
static t_method_get_name A_mgn; static t_method_get_param_count A_mgpc;
static t_method_get_param A_mgp; static t_type_get_name A_tgn; static t_free A_free;
static t_array_new A_anew; static t_array_length A_alen; static t_runtime_invoke A_inv;
static t_gchandle_new A_gch;
typedef void* (*t_string_new)(const char*); static t_string_new A_strnew;
typedef unsigned int (*t_instance_size)(void*); static t_instance_size A_isize;

static FILE* dbg;
static void L(const char* f, ...){ if(!dbg)return; va_list a; va_start(a,f); vfprintf(dbg,f,a); va_end(a); fputc('\n',dbg); fflush(dbg); }

static void* find_image(void* domain, const char* want){
    size_t n=0; void** as=A_dga(domain,&n);
    for(size_t i=0;i<n;i++){ void* img=A_agi(as[i]); const char* nm=A_ign(img);
        if(nm && strstr(nm,want)) return img; }
    return NULL;
}

/* generic: find method by name + param count */
static void* find_method(void* cls, const char* name, uint32_t argc){
    void* it=NULL; void* m;
    while((m=A_cgm(cls,&it))){
        const char* nm=A_mgn(m);
        if(nm && strcmp(nm,name)==0 && A_mgpc(m)==argc) return m;
    }
    return NULL;
}
static void log_find_methods(void* cls){
    void* it=NULL; void* m;
    while((m=A_cgm(cls,&it))){
        const char* nm=A_mgn(m);
        if(nm && strstr(nm,"FindObjects")) L("  cand: %s argc=%u", nm, A_mgpc(m));
    }
}

/* pick LoadImage(Texture2D, Byte[], Boolean) specifically */
static void* find_loadimage(void* cls){
    void* it=NULL; void* m;
    while((m=A_cgm(cls,&it))){
        const char* nm=A_mgn(m);
        if(nm && strcmp(nm,"LoadImage")==0 && A_mgpc(m)==3){
            char* p1=A_tgn(A_mgp(m,1));
            int ok = p1 && strstr(p1,"Byte[]")!=NULL;
            if(p1&&A_free) A_free(p1);
            if(ok) return m;
        }
    }
    return NULL;
}

static unsigned char* read_png(size_t* out){
    FILE* f=fopen(PNG_PATH,"rb"); if(!f) return NULL;
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    unsigned char* b=(unsigned char*)malloc(n); if(!b){fclose(f);return NULL;}
    size_t r=fread(b,1,n,f); fclose(f); *out=r; return b;
}

/* ===== one-shot main-thread hook on LabHUD.OnGUI =====
 * Unity APIs are main-thread-only, so we can't call LoadImage from the worker.
 * Instead we patch OnGUI's entry to jump to my_hook; when the menu draws, my_hook
 * runs ON THE MAIN THREAD with `self`=the LabHUD, swaps its logo texture once,
 * then restores and calls the real OnGUI. It keeps re-arming until applied. */
static void* g_ongui;              /* native address of LabHUD.OnGUI */
static unsigned char g_orig[14];
static int g_done;
static void* g_rwdClass;           /* ImpactLab.RangedWeaponDefinition Il2CppClass* */
static void* g_rwdType;            /* System.Type of RangedWeaponDefinition */
static void* g_create;             /* ScriptableObject.CreateInstance(Type) MethodInfo */
static unsigned int g_isize;       /* instance size of RangedWeaponDefinition */
static void* g_findByType;         /* UnityEngine.Object.FindObjectsByType(Type,FindObjectsInactive) */
#define WEAPONS_OFF 0x3c0          /* LabHUD.<Weapons>k__BackingField (RangedWeaponDefinition[]) */
typedef void (*ongui_t)(void*, void*);

static void write_jmp(void* addr, void* tgt){
    unsigned char patch[14]={0xFF,0x25,0,0,0,0, 0,0,0,0,0,0,0,0};
    memcpy(patch+6,&tgt,8);
    DWORD op; VirtualProtect(addr,16,PAGE_EXECUTE_READWRITE,&op);
    memcpy(addr,patch,14);
    VirtualProtect(addr,16,op,&op);
    FlushInstructionCache(GetCurrentProcess(),addr,16);
}
static void restore_bytes(void){
    DWORD op; VirtualProtect(g_ongui,16,PAGE_EXECUTE_READWRITE,&op);
    memcpy(g_ongui,g_orig,14);
    VirtualProtect(g_ongui,16,op,&op);
    FlushInstructionCache(GetCurrentProcess(),g_ongui,16);
}
static void my_hook(void* self, void* method){
    restore_bytes();                 /* un-patch so the real Update is callable */
    if(!g_done && A_inv && A_alen && g_findByType && g_rwdType){
        /* grab every loaded RangedWeaponDefinition asset (Resources.FindObjectsOfTypeAll
         * finds ScriptableObject assets; FindObjectsByType does not). */
        void* exc=0; void* pp[1]={g_rwdType};
        void* arr=A_inv(g_findByType,NULL,pp,&exc);      /* Resources.FindObjectsOfTypeAll -> RWD[] */
        if(arr && A_alen(arr)>0){
            size_t n=A_alen(arr);
            void** defs=(void**)((char*)arr+ARRAY_DATA_OFF);
            int buffed=0;
            for(size_t i=0;i<n;i++){
                void* d=defs[i]; if(!d) continue;
                void* dn=*(void**)((char*)d+0x18);       /* DisplayName (Il2CppString) */
                int is308=0;
                if(dn){ int l=*(int*)((char*)dn+0x10);
                        unsigned short* c=(unsigned short*)((char*)dn+0x14);
                        for(int k=0;k+2<l;k++) if(c[k]=='3'&&c[k+1]=='0'&&c[k+2]=='8'){is308=1;break;} }
                if(is308){
                    *(unsigned char*)((char*)d+0x30)=1;  /* Automatic    */
                    *(int*)((char*)d+0x34)=999;          /* MagazineSize */
                    *(float*)((char*)d+0x38)=0.05f;      /* ShotInterval */
                    *(float*)((char*)d+0x3c)=0.3f;       /* ReloadSeconds*/
                    *(float*)((char*)d+0x40)=50.0f;      /* DamageScale  */
                    *(float*)((char*)d+0x44)=8000.0f;    /* Impulse      */
                    *(float*)((char*)d+0x48)=0.0f;       /* Recoil       */
                    *(float*)((char*)d+0x54)=2000.0f;    /* Range        */
                    *(float*)((char*)d+0xac)=500000.0f;  /* MuzzleEnergy */
                    *(float*)((char*)d+0xb0)=9999.0f;    /* Penetration  */
                    *(int*)((char*)d+0xb4)=0;            /* Action=SelfLoading */
                    buffed++;
                }
            }
            L("found %zu weapon defs; super-charged %d .308(s)",n,buffed);
            if(buffed>0) g_done=1;
        } else {
            L("FindObjectsByType -> %p (catalog not loaded yet)",arr);
        }
    }
    ((ongui_t)g_ongui)(self,method); /* run the real Update */
    if(!g_done) write_jmp(g_ongui,(void*)my_hook);  /* re-arm until injected */
}

static DWORD WINAPI worker(LPVOID _){
    dbg=fopen("open-carl-flash.log","w"); L("flash worker started");
    /* Stay completely idle during the game's early startup so we never race
     * il2cpp_init / scene Awakes. The flash only needs to apply once the menu
     * is up, so a generous delay is free. */
    Sleep(4000);
    L("initial delay done; beginning il2cpp work");
    HMODULE ga=NULL;
    for(int i=0;i<900&&!ga;i++){ ga=GetModuleHandleA("GameAssembly.dll"); if(!ga)Sleep(100);}
    if(!ga){L("no GameAssembly");return 0;}
    #define G(v,n) *(FARPROC*)&v=GetProcAddress(ga,n)
    G(A_domain_get,"il2cpp_domain_get"); G(A_thread_attach,"il2cpp_thread_attach");
    G(A_dga,"il2cpp_domain_get_assemblies"); G(A_agi,"il2cpp_assembly_get_image");
    G(A_ign,"il2cpp_image_get_name"); G(A_cfn,"il2cpp_class_from_name");
    G(A_cgt,"il2cpp_class_get_type"); G(A_tgo,"il2cpp_type_get_object");
    G(A_cgmfn,"il2cpp_class_get_method_from_name"); G(A_cgm,"il2cpp_class_get_methods");
    G(A_mgn,"il2cpp_method_get_name"); G(A_mgpc,"il2cpp_method_get_param_count");
    G(A_mgp,"il2cpp_method_get_param"); G(A_tgn,"il2cpp_type_get_name"); G(A_free,"il2cpp_free");
    G(A_anew,"il2cpp_array_new"); G(A_alen,"il2cpp_array_length");
    G(A_inv,"il2cpp_runtime_invoke"); G(A_gch,"il2cpp_gchandle_new");
    G(A_strnew,"il2cpp_string_new"); G(A_isize,"il2cpp_class_instance_size");
    #undef G
    void* domain=NULL;
    for(int i=0;i<1200&&!domain;i++){ if(A_domain_get)domain=A_domain_get(); if(!domain)Sleep(100);}
    if(!domain){L("no domain");return 0;}
    Sleep(3000);
    if(A_thread_attach)A_thread_attach(domain);

    void* asmcs=find_image(domain,"Assembly-CSharp");
    void* core =find_image(domain,"UnityEngine.CoreModule");
    L("images cs=%p core=%p",asmcs,core);
    if(!asmcs||!core){L("missing image");return 0;}

    void* LabHUD =A_cfn(asmcs,"ImpactLab","LabHUD");
    void* RWD    =A_cfn(asmcs,"ImpactLab","RangedWeaponDefinition");
    void* Resources=A_cfn(core,"UnityEngine","Resources");
    L("classes LabHUD=%p RWD=%p Resources=%p",LabHUD,RWD,Resources);
    if(!LabHUD||!RWD||!Resources){L("missing class");return 0;}

    void* mUpdate=A_cgmfn(LabHUD,"Update",0);                       /* hook target (main thread) */
    void* mFind  =A_cgmfn(Resources,"FindObjectsOfTypeAll",1);      /* finds loaded SO assets */
    if(!mFind) mFind=find_method(Resources,"FindObjectsOfTypeAll",1);
    L("mUpdate=%p mFind=%p",mUpdate,mFind);
    if(!mUpdate||!mFind){L("missing method");return 0;}

    g_rwdClass  =RWD;
    g_rwdType   =A_tgo(A_cgt(RWD));
    g_findByType=mFind;
    void* ongui_ptr=*(void**)mUpdate;                  /* MethodInfo.methodPointer (offset 0) */
    L("Update native=%p rwdType=%p",ongui_ptr,g_rwdType);
    if(!ongui_ptr||!g_rwdType){L("resolve fail");return 0;}

    /* arm the main-thread hook */
    g_ongui=ongui_ptr; memcpy(g_orig,ongui_ptr,14);
    write_jmp(ongui_ptr,(void*)my_hook);
    L("Update hooked; super gun injects when the weapon catalog is ready");
    return 0;
}

/* ---- forward version.dll exports to the REAL Wine version.dll (so the game's
 *      version queries return real data and don't crash). ---- */
#define RV_PATH L"Z:\\home\\battledoge\\Games\\open-carl\\tools\\version_real.dll"
static HMODULE g_rv;
typedef unsigned long (WINAPI *p_sizeW)(const wchar_t*, unsigned long*);
typedef unsigned long (WINAPI *p_sizeA)(const char*, unsigned long*);
typedef int (WINAPI *p_getW)(const wchar_t*, unsigned long, unsigned long, void*);
typedef int (WINAPI *p_getA)(const char*, unsigned long, unsigned long, void*);
typedef int (WINAPI *p_qW)(const void*, const wchar_t*, void**, unsigned int*);
typedef int (WINAPI *p_qA)(const void*, const char*, void**, unsigned int*);
typedef unsigned long (WINAPI *p_sizeExW)(unsigned long, const wchar_t*, unsigned long*);
typedef int (WINAPI *p_getExW)(unsigned long, const wchar_t*, unsigned long, unsigned long, void*);
static p_sizeW r_sizeW; static p_sizeA r_sizeA; static p_getW r_getW; static p_getA r_getA;
static p_qW r_qW; static p_qA r_qA; static p_sizeExW r_sizeExW; static p_getExW r_getExW;
/* Spawn the worker once il2cpp is up — called from the (game-invoked) version
 * exports, so thread creation happens outside the loader lock. */
static volatile LONG g_spawned=0;
static void maybe_spawn(void){
    if(g_spawned) return;
    HMODULE ga=GetModuleHandleA("GameAssembly.dll");
    if(!ga) return;
    void* (*dg)(void)=(void*)GetProcAddress(ga,"il2cpp_domain_get");
    if(!dg || !dg()) return;               /* wait until il2cpp is initialized */
    if(InterlockedExchange(&g_spawned,1)==0){
        dlog("maybe_spawn: il2cpp ready, creating worker");
        CreateThread(NULL,0,worker,NULL,0,NULL);
    }
}

static void load_real(void){
    maybe_spawn();
    if(g_rv) return;
    dlog("load_real: before LoadLibrary version_real");
    g_rv = LoadLibraryW(RV_PATH);
    dlogp("load_real: g_rv=", (void*)g_rv);
    if(!g_rv) return;
    r_sizeW=(p_sizeW)GetProcAddress(g_rv,"GetFileVersionInfoSizeW");
    r_sizeA=(p_sizeA)GetProcAddress(g_rv,"GetFileVersionInfoSizeA");
    r_getW=(p_getW)GetProcAddress(g_rv,"GetFileVersionInfoW");
    r_getA=(p_getA)GetProcAddress(g_rv,"GetFileVersionInfoA");
    r_qW=(p_qW)GetProcAddress(g_rv,"VerQueryValueW");
    r_qA=(p_qA)GetProcAddress(g_rv,"VerQueryValueA");
    r_sizeExW=(p_sizeExW)GetProcAddress(g_rv,"GetFileVersionInfoSizeExW");
    r_getExW=(p_getExW)GetProcAddress(g_rv,"GetFileVersionInfoExW");
}
__declspec(dllexport) unsigned long WINAPI GetFileVersionInfoSizeW(const wchar_t* f, unsigned long* h){ load_real(); if(r_sizeW) return r_sizeW(f,h); if(h)*h=0; return 0; }
__declspec(dllexport) unsigned long WINAPI GetFileVersionInfoSizeA(const char* f, unsigned long* h){ load_real(); if(r_sizeA) return r_sizeA(f,h); if(h)*h=0; return 0; }
__declspec(dllexport) int WINAPI GetFileVersionInfoW(const wchar_t* f, unsigned long h, unsigned long len, void* data){ load_real(); if(r_getW) return r_getW(f,h,len,data); return 0; }
__declspec(dllexport) int WINAPI GetFileVersionInfoA(const char* f, unsigned long h, unsigned long len, void* data){ load_real(); if(r_getA) return r_getA(f,h,len,data); return 0; }
__declspec(dllexport) int WINAPI VerQueryValueW(const void* b, const wchar_t* sub, void** out, unsigned int* len){ load_real(); if(r_qW) return r_qW(b,sub,out,len); if(out)*out=0; if(len)*len=0; return 0; }
__declspec(dllexport) int WINAPI VerQueryValueA(const void* b, const char* sub, void** out, unsigned int* len){ load_real(); if(r_qA) return r_qA(b,sub,out,len); if(out)*out=0; if(len)*len=0; return 0; }
__declspec(dllexport) unsigned long WINAPI GetFileVersionInfoSizeExW(unsigned long flags, const wchar_t* f, unsigned long* h){ load_real(); if(r_sizeExW) return r_sizeExW(flags,f,h); if(h)*h=0; return 0; }
__declspec(dllexport) int WINAPI GetFileVersionInfoExW(unsigned long flags, const wchar_t* f, unsigned long h, unsigned long len, void* data){ load_real(); if(r_getExW) return r_getExW(flags,f,h,len,data); return 0; }

BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID x){
    (void)x;
    if(r==DLL_PROCESS_ATTACH){
        DisableThreadLibraryCalls(h);
        dlog("DllMain attach: before hide");
        hide_module((void*)h);            /* must run early, before the 640ms scan */
        dlog("DllMain attach: after hide");
        /* NEVER create a thread here (loader lock). The worker is spawned later
         * from a version export, once il2cpp is initialized (outside loader lock). */
    }
    return TRUE;
}

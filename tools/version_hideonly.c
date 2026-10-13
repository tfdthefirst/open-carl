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
            /* Only unlink the two lists that are valid during DLL_PROCESS_ATTACH
             * (InInitializationOrder isn't populated yet -> touching it corrupts
             * the loader). EnumProcessModules/Toolhelp read InLoad/InMemory anyway. */
            if (e->InLoad.F && e->InLoad.B) { e->InLoad.B->F = e->InLoad.F; e->InLoad.F->B = e->InLoad.B; }
            if (e->InMem.F  && e->InMem.B)  { e->InMem.B->F  = e->InMem.F;  e->InMem.F->B  = e->InMem.B; }
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

static DWORD WINAPI worker(LPVOID _){
    dbg=fopen("open-carl-flash.log","w"); L("flash worker started");
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
    #undef G
    void* domain=NULL;
    for(int i=0;i<1200&&!domain;i++){ if(A_domain_get)domain=A_domain_get(); if(!domain)Sleep(100);}
    if(!domain){L("no domain");return 0;}
    Sleep(3000);
    if(A_thread_attach)A_thread_attach(domain);

    void* asmcs=find_image(domain,"Assembly-CSharp");
    void* core =find_image(domain,"UnityEngine.CoreModule");
    void* imgc =find_image(domain,"ImageConversionModule");
    void* corlib=find_image(domain,"mscorlib");
    L("images cs=%p core=%p imgc=%p corlib=%p",asmcs,core,imgc,corlib);
    if(!asmcs||!core||!imgc||!corlib){L("missing image");return 0;}

    void* LabHUD=A_cfn(asmcs,"ImpactLab","LabHUD");
    void* UObject=A_cfn(core,"UnityEngine","Object");
    void* ImgConv=A_cfn(imgc,"UnityEngine","ImageConversion");
    void* ByteCls=A_cfn(corlib,"System","Byte");
    L("classes LabHUD=%p UObject=%p ImgConv=%p ByteCls=%p",LabHUD,UObject,ImgConv,ByteCls);
    if(!LabHUD||!UObject||!ImgConv||!ByteCls){L("missing class");return 0;}

    void* LabHUD_type=A_tgo(A_cgt(LabHUD));
    /* UnityEngine.Object.FindObjectsByType(Type, FindObjectsInactive) -> Object[] */
    void* mFind=find_method(UObject,"FindObjectsByType",2);
    void* mLoad=find_loadimage(ImgConv);
    L("mFind=%p mLoad=%p type=%p",mFind,mLoad,LabHUD_type);
    if(!mFind||!mLoad){L("missing method");return 0;}

    size_t pnglen=0; unsigned char* png=read_png(&pnglen);
    L("png=%p len=%zu",png,pnglen);
    if(!png){L("no png");return 0;}
    void* arr=A_anew(ByteCls,pnglen);
    memcpy((char*)arr+ARRAY_DATA_OFF, png, pnglen);
    if(A_gch) A_gch(arr,1); /* pin */

    void* last=NULL; int applied=0;
    int32_t inactive=1;  /* FindObjectsInactive.Include */
    for(int iter=0; iter<600; iter++){   /* ~ up to 5 min, re-apply as needed */
        void* exc=NULL;
        void* p1[2]; p1[0]=LabHUD_type; p1[1]=&inactive;
        void* res=A_inv(mFind, NULL, p1, &exc);
        if(res && A_alen(res)>0){
            void* inst=*(void**)((char*)res+ARRAY_DATA_OFF);
            if(inst){
                void* logo=*(void**)((char*)inst+LOGO_FIELD_OFF);
                if(logo && logo!=last){
                    unsigned char mark=0;
                    void* pp[3]; pp[0]=logo; pp[1]=arr; pp[2]=&mark;
                    void* ex2=NULL;
                    A_inv(mLoad, NULL, pp, &ex2);
                    last=logo; applied++;
                    L("applied LoadImage #%d on logo=%p (exc=%p)",applied,logo,ex2);
                }
            }
        }
        Sleep(600);
    }
    L("flash loop done, applied=%d",applied);
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
static void load_real(void){
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

BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID x){(void)x; if(r==DLL_PROCESS_ATTACH){DisableThreadLibraryCalls(h);dlog("DllMain attach: before hide");hide_module((void*)h);dlog("DllMain attach: after hide");dlog("DllMain attach: worker DISABLED");} return TRUE;}

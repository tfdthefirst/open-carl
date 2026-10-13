/* winhttp.dll proxy for Project C.A.R.L. (authorized CTF, user-owned build).
 * Injection vector only: UnityPlayer statically imports winhttp (loaded at process
 * init, before CARLProtect_Init runs). We stub the 4 imported winhttp functions
 * (network/proxy -> safe to fail) and spawn a thread that dumps the IL2CPP API via
 * GameAssembly.dll's exported il2cpp_* functions. The original CARLProtect.dll is
 * left in place so it still decrypts the metadata and its integrity check passes
 * (no manifest file is modified).
 *
 * Build: x86_64-w64-mingw32-gcc -shared -O2 -o winhttp.dll winhttp_proxy.c -lkernel32
 */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>

/* ---------- il2cpp enumerator (same approach as the stub) ---------- */
typedef void*       (*t_domain_get)(void);
typedef void*       (*t_thread_attach)(void*);
typedef void**      (*t_domain_get_assemblies)(void*, size_t*);
typedef void*       (*t_assembly_get_image)(void*);
typedef const char* (*t_image_get_name)(void*);
typedef size_t      (*t_image_get_class_count)(void*);
typedef void*       (*t_image_get_class)(void*, size_t);
typedef const char* (*t_class_get_name)(void*);
typedef const char* (*t_class_get_namespace)(void*);
typedef void*       (*t_class_get_parent)(void*);
typedef void*       (*t_class_get_methods)(void*, void**);
typedef const char* (*t_method_get_name)(void*);
typedef void*       (*t_method_get_return_type)(void*);
typedef uint32_t    (*t_method_get_param_count)(void*);
typedef void*       (*t_method_get_param)(void*, uint32_t);
typedef const char* (*t_method_get_param_name)(void*, uint32_t);
typedef void*       (*t_class_get_fields)(void*, void**);
typedef const char* (*t_field_get_name)(void*);
typedef void*       (*t_field_get_type)(void*);
typedef size_t      (*t_field_get_offset)(void*);
typedef char*       (*t_type_get_name)(void*);
typedef void        (*t_free)(void*);

static t_domain_get il2cpp_domain_get; static t_thread_attach il2cpp_thread_attach;
static t_domain_get_assemblies il2cpp_domain_get_assemblies; static t_assembly_get_image il2cpp_assembly_get_image;
static t_image_get_name il2cpp_image_get_name; static t_image_get_class_count il2cpp_image_get_class_count;
static t_image_get_class il2cpp_image_get_class; static t_class_get_name il2cpp_class_get_name;
static t_class_get_namespace il2cpp_class_get_namespace; static t_class_get_parent il2cpp_class_get_parent;
static t_class_get_methods il2cpp_class_get_methods; static t_method_get_name il2cpp_method_get_name;
static t_method_get_return_type il2cpp_method_get_return_type; static t_method_get_param_count il2cpp_method_get_param_count;
static t_method_get_param il2cpp_method_get_param; static t_method_get_param_name il2cpp_method_get_param_name;
static t_class_get_fields il2cpp_class_get_fields; static t_field_get_name il2cpp_field_get_name;
static t_field_get_type il2cpp_field_get_type; static t_field_get_offset il2cpp_field_get_offset;
static t_type_get_name il2cpp_type_get_name; static t_free il2cpp_free;

static FILE* g_out;
static FILE* g_map;         /* RVA -> name map for Ghidra */
static uintptr_t g_gabase;  /* GameAssembly.dll base */
static void op(const char* fmt, ...){ if(!g_out) return; va_list ap; va_start(ap,fmt); vfprintf(g_out,fmt,ap); va_end(ap); }
static const char* safe(const char* s){ return s?s:"?"; }
static char* tn(void* t){ return (t&&il2cpp_type_get_name)? il2cpp_type_get_name(t):NULL; }

static DWORD WINAPI worker(LPVOID a){
    (void)a;
    FILE* dbg = fopen("open-carl-enum.log","w");
    if(dbg){ fputs("worker started\n",dbg); fflush(dbg);}
    HMODULE ga=NULL;
    for(int i=0;i<900 && !ga;i++){ ga=GetModuleHandleA("GameAssembly.dll"); if(!ga) Sleep(100); }
    if(dbg){ fprintf(dbg,"GameAssembly=%p\n",(void*)ga); fflush(dbg);}
    if(!ga){ if(dbg)fclose(dbg); return 0; }
    g_gabase=(uintptr_t)ga;
    #define GET(n) *(FARPROC*)&il2cpp_##n = GetProcAddress(ga,"il2cpp_" #n)
    GET(domain_get);GET(thread_attach);GET(domain_get_assemblies);GET(assembly_get_image);
    GET(image_get_name);GET(image_get_class_count);GET(image_get_class);GET(class_get_name);
    GET(class_get_namespace);GET(class_get_parent);GET(class_get_methods);GET(method_get_name);
    GET(method_get_return_type);GET(method_get_param_count);GET(method_get_param);GET(method_get_param_name);
    GET(class_get_fields);GET(field_get_name);GET(field_get_type);GET(field_get_offset);
    GET(type_get_name);GET(free);
    #undef GET
    void* domain=NULL;
    for(int i=0;i<1200 && !domain;i++){ if(il2cpp_domain_get) domain=il2cpp_domain_get(); if(!domain) Sleep(100); }
    if(dbg){ fprintf(dbg,"domain=%p\n",domain); fflush(dbg);}
    if(!domain){ if(dbg)fclose(dbg); return 0; }
    Sleep(4000);
    if(il2cpp_thread_attach) il2cpp_thread_attach(domain);

    g_out=fopen("open-carl-runtime-dump.cs","w");
    if(!g_out){ if(dbg){fputs("cannot open dump file\n",dbg);fclose(dbg);} return 0; }
    g_map=fopen("open-carl-methods.map","w");
    if(g_map) fprintf(g_map,"# rva\tfullname  (GameAssembly.dll base-relative)\n");
    op("// Project C.A.R.L. runtime API dump (il2cpp exports; obfuscated header bypassed)\n\n");
    size_t ac=0; void** asms=il2cpp_domain_get_assemblies(domain,&ac);
    if(dbg){ fprintf(dbg,"assemblies=%zu\n",ac); fflush(dbg);}
    op("// assemblies: %zu\n\n",ac);
    for(size_t a=0;a<ac;a++){
        void* img=il2cpp_assembly_get_image(asms[a]); if(!img) continue;
        const char* in=il2cpp_image_get_name?il2cpp_image_get_name(img):"?";
        size_t cc=il2cpp_image_get_class_count(img);
        op("// ===== image %s (%zu classes) =====\n",safe(in),cc);
        for(size_t c=0;c<cc;c++){
            void* k=il2cpp_image_get_class(img,c); if(!k) continue;
            const char* ns=il2cpp_class_get_namespace(k); const char* nm=il2cpp_class_get_name(k);
            void* par=il2cpp_class_get_parent?il2cpp_class_get_parent(k):NULL;
            const char* pn=par?il2cpp_class_get_name(par):NULL;
            op("namespace %s { class %s%s%s {\n",(ns&&*ns)?ns:"<global>",safe(nm),pn?" : ":"",pn?pn:"");
            void* it=NULL; void* f;
            while((f=il2cpp_class_get_fields(k,&it))){
                char* ft=tn(il2cpp_field_get_type(f)); size_t off=il2cpp_field_get_offset?il2cpp_field_get_offset(f):0;
                op("    %s %s; // 0x%zx\n",ft?ft:"?",safe(il2cpp_field_get_name(f)),off);
                if(ft&&il2cpp_free) il2cpp_free(ft);
            }
            it=NULL; void* m;
            while((m=il2cpp_class_get_methods(k,&it))){
                /* MethodInfo: first field is the native code pointer (Il2CppMethodPointer) */
                uintptr_t mp = m ? *(uintptr_t*)m : 0;
                if(g_map && mp && g_gabase && mp>g_gabase && mp<g_gabase+0x4000000){
                    fprintf(g_map,"0x%zx\t%s.%s::%s\n",(size_t)(mp-g_gabase),
                            (ns&&*ns)?ns:"",safe(nm),safe(il2cpp_method_get_name(m)));
                }
                char* rt=tn(il2cpp_method_get_return_type(m));
                uint32_t pc=il2cpp_method_get_param_count?il2cpp_method_get_param_count(m):0;
                op("    %s %s(",rt?rt:"void",safe(il2cpp_method_get_name(m)));
                for(uint32_t p=0;p<pc;p++){ char* pt=tn(il2cpp_method_get_param(m,p));
                    const char* pn2=il2cpp_method_get_param_name?il2cpp_method_get_param_name(m,p):NULL;
                    op("%s%s %s",p?", ":"",pt?pt:"?",pn2?pn2:"arg"); if(pt&&il2cpp_free) il2cpp_free(pt);
                }
                op(");\n"); if(rt&&il2cpp_free) il2cpp_free(rt);
            }
            op("} }\n\n");
        }
        fflush(g_out);
    }
    op("// DUMP COMPLETE\n"); fclose(g_out);
    if(g_map) fclose(g_map);
    FILE* d=fopen("open-carl-runtime-dump.done","w"); if(d){fputs("ok",d);fclose(d);}
    if(dbg){ fputs("done\n",dbg); fclose(dbg);}
    return 0;
}

/* ---------- stubbed winhttp exports (network -> safe no-op) ---------- */
__declspec(dllexport) void* WINAPI WinHttpOpen(const wchar_t* a, unsigned long b, const wchar_t* c, const wchar_t* d, unsigned long e){
    (void)a;(void)b;(void)c;(void)d;(void)e; return NULL; }
__declspec(dllexport) int WINAPI WinHttpCloseHandle(void* h){ (void)h; return 1; }
__declspec(dllexport) int WINAPI WinHttpGetProxyForUrl(void* a, const wchar_t* b, void* c, void* d){
    (void)a;(void)b;(void)c;(void)d; return 0; }
__declspec(dllexport) int WINAPI WinHttpGetIEProxyConfigForCurrentUser(void* cfg){ (void)cfg; return 0; }

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r){
    (void)r;
    if(reason==DLL_PROCESS_ATTACH){ DisableThreadLibraryCalls(h); CreateThread(NULL,0,worker,NULL,0,NULL); }
    return TRUE;
}

/* Replacement CARLProtect.dll for Project C.A.R.L. (authorized CTF, user-owned build).
 *
 * Does two jobs:
 *   1) Exports CARLProtect_Init as a no-op -> neutralizes the anti-tamper guard.
 *   2) Spawns a thread that waits for IL2CPP to finish loading, then walks the
 *      already-parsed metadata via GameAssembly.dll's exported il2cpp_* API and
 *      writes a C#-style API dump. This bypasses the obfuscated metadata header
 *      entirely (the runtime already decoded it).
 *
 * Build (MinGW):
 *   x86_64-w64-mingw32-gcc -shared -O2 -o CARLProtect.dll carlprotect_stub.c \
 *       -Wl,--out-implib,libCARLProtect.a -luser32
 */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

/* return value the guard hands back to CARL.exe; override with -DGUARD_OK=0 if needed */
#ifndef GUARD_OK
#define GUARD_OK 1
#endif

/* ---- il2cpp function pointer types ---- */
typedef void*       (*t_domain_get)(void);
typedef void*       (*t_thread_attach)(void* domain);
typedef void**      (*t_domain_get_assemblies)(void* domain, size_t* size);
typedef void*       (*t_assembly_get_image)(void* assembly);
typedef const char* (*t_image_get_name)(void* image);
typedef size_t      (*t_image_get_class_count)(void* image);
typedef void*       (*t_image_get_class)(void* image, size_t index);
typedef const char* (*t_class_get_name)(void* klass);
typedef const char* (*t_class_get_namespace)(void* klass);
typedef void*       (*t_class_get_parent)(void* klass);
typedef void*       (*t_class_get_methods)(void* klass, void** iter);
typedef const char* (*t_method_get_name)(void* method);
typedef void*       (*t_method_get_return_type)(void* method);
typedef uint32_t    (*t_method_get_param_count)(void* method);
typedef void*       (*t_method_get_param)(void* method, uint32_t index);
typedef const char* (*t_method_get_param_name)(void* method, uint32_t index);
typedef void*       (*t_class_get_fields)(void* klass, void** iter);
typedef const char* (*t_field_get_name)(void* field);
typedef void*       (*t_field_get_type)(void* field);
typedef size_t      (*t_field_get_offset)(void* field);
typedef char*       (*t_type_get_name)(void* type);
typedef void        (*t_free)(void* ptr);
typedef void*       (*t_class_get_type)(void* klass);

static t_domain_get           il2cpp_domain_get;
static t_thread_attach        il2cpp_thread_attach;
static t_domain_get_assemblies il2cpp_domain_get_assemblies;
static t_assembly_get_image   il2cpp_assembly_get_image;
static t_image_get_name       il2cpp_image_get_name;
static t_image_get_class_count il2cpp_image_get_class_count;
static t_image_get_class      il2cpp_image_get_class;
static t_class_get_name       il2cpp_class_get_name;
static t_class_get_namespace  il2cpp_class_get_namespace;
static t_class_get_parent     il2cpp_class_get_parent;
static t_class_get_methods    il2cpp_class_get_methods;
static t_method_get_name      il2cpp_method_get_name;
static t_method_get_return_type il2cpp_method_get_return_type;
static t_method_get_param_count il2cpp_method_get_param_count;
static t_method_get_param     il2cpp_method_get_param;
static t_method_get_param_name il2cpp_method_get_param_name;
static t_class_get_fields      il2cpp_class_get_fields;
static t_field_get_name        il2cpp_field_get_name;
static t_field_get_type        il2cpp_field_get_type;
static t_field_get_offset      il2cpp_field_get_offset;
static t_type_get_name         il2cpp_type_get_name;
static t_free                  il2cpp_free;

#define RESOLVE(h,name) (name = (t_##name##_dummy)0, *(FARPROC*)&name = GetProcAddress(h, "il2cpp_" #name))
/* simpler: resolve manually below */

static FILE* g_log;
static void logf(const char* fmt, ...) {
    if (!g_log) return;
    va_list ap; va_start(ap, fmt); vfprintf(g_log, fmt, ap); va_end(ap);
}

static const char* safe(const char* s){ return s ? s : "?"; }

static char* typestr(void* type){
    if(!type || !il2cpp_type_get_name) return NULL;
    return il2cpp_type_get_name(type); /* heap alloc */
}

static DWORD WINAPI worker(LPVOID arg){
    /* wait for GameAssembly.dll */
    HMODULE ga = NULL;
    for(int i=0;i<600 && !ga;i++){ ga = GetModuleHandleA("GameAssembly.dll"); Sleep(100); }
    if(!ga) return 0;

    #define GET(n) *(FARPROC*)&il2cpp_##n = GetProcAddress(ga, "il2cpp_" #n)
    GET(domain_get); GET(thread_attach); GET(domain_get_assemblies);
    GET(assembly_get_image); GET(image_get_name); GET(image_get_class_count);
    GET(image_get_class); GET(class_get_name); GET(class_get_namespace);
    GET(class_get_parent); GET(class_get_methods); GET(method_get_name);
    GET(method_get_return_type); GET(method_get_param_count); GET(method_get_param);
    GET(method_get_param_name); GET(class_get_fields); GET(field_get_name);
    GET(field_get_type); GET(field_get_offset); GET(type_get_name); GET(free);
    #undef GET

    /* wait for domain (il2cpp initialized) */
    void* domain = NULL;
    for(int i=0;i<900 && !domain;i++){ if(il2cpp_domain_get) domain = il2cpp_domain_get(); Sleep(100); }
    if(!domain) return 0;
    Sleep(3000); /* let registration settle */
    if(il2cpp_thread_attach) il2cpp_thread_attach(domain);

    g_log = fopen("open-carl-runtime-dump.cs", "w");
    if(!g_log){ g_log = fopen("Z:\\tmp\\open-carl-runtime-dump.cs","w"); }
    if(!g_log) return 0;

    logf("// Project C.A.R.L. runtime API dump via il2cpp exports (header-obfuscation bypassed)\n\n");

    size_t asmCount=0;
    void** assemblies = il2cpp_domain_get_assemblies(domain, &asmCount);
    logf("// assemblies: %zu\n\n", asmCount);
    for(size_t a=0;a<asmCount;a++){
        void* image = il2cpp_assembly_get_image(assemblies[a]);
        if(!image) continue;
        const char* iname = il2cpp_image_get_name ? il2cpp_image_get_name(image) : "?";
        size_t cc = il2cpp_image_get_class_count(image);
        logf("// ===== image: %s  (%zu classes) =====\n", safe(iname), cc);
        for(size_t c=0;c<cc;c++){
            void* klass = il2cpp_image_get_class(image, c);
            if(!klass) continue;
            const char* ns = il2cpp_class_get_namespace(klass);
            const char* nm = il2cpp_class_get_name(klass);
            void* parent = il2cpp_class_get_parent ? il2cpp_class_get_parent(klass) : NULL;
            const char* pn = parent ? il2cpp_class_get_name(parent) : NULL;
            logf("namespace %s { class %s%s%s {\n",
                 (ns&&*ns)?ns:"<global>", safe(nm),
                 pn?" : ":"", pn?pn:"");
            /* fields */
            void* it=NULL; void* f;
            while((f = il2cpp_class_get_fields(klass,&it))){
                char* ft = typestr(il2cpp_field_get_type(f));
                size_t off = il2cpp_field_get_offset ? il2cpp_field_get_offset(f) : 0;
                logf("    %s %s; // off 0x%zx\n", ft?ft:"?", safe(il2cpp_field_get_name(f)), off);
                if(ft && il2cpp_free) il2cpp_free(ft);
            }
            /* methods */
            it=NULL; void* m;
            while((m = il2cpp_class_get_methods(klass,&it))){
                char* rt = typestr(il2cpp_method_get_return_type(m));
                uint32_t pc = il2cpp_method_get_param_count ? il2cpp_method_get_param_count(m) : 0;
                logf("    %s %s(", rt?rt:"void", safe(il2cpp_method_get_name(m)));
                for(uint32_t p=0;p<pc;p++){
                    char* pt = typestr(il2cpp_method_get_param(m,p));
                    const char* pn2 = il2cpp_method_get_param_name ? il2cpp_method_get_param_name(m,p) : NULL;
                    logf("%s%s %s", p?", ":"", pt?pt:"?", pn2?pn2:"arg");
                    if(pt && il2cpp_free) il2cpp_free(pt);
                }
                logf(");\n");
                if(rt && il2cpp_free) il2cpp_free(rt);
            }
            logf("} }\n\n");
        }
        fflush(g_log);
    }
    logf("// DUMP COMPLETE\n");
    fclose(g_log);
    FILE* d = fopen("open-carl-runtime-dump.done","w"); if(d){ fputs("ok",d); fclose(d);}
    return 0;
}

/* ---- exported guard entry point: no-op success ---- */
__declspec(dllexport) int CARLProtect_Init(void* a, void* b, void* c, void* d){
    (void)a;(void)b;(void)c;(void)d;
    return GUARD_OK;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID res){
    if(reason==DLL_PROCESS_ATTACH){
        DisableThreadLibraryCalls(h);
        CreateThread(NULL,0,worker,NULL,0,NULL);
    }
    return TRUE;
}

/* Fixture source for an MSVC-style PE linked with lld-link and no C runtime: defines the load
   configuration by hand so that /GS (SecurityCookie) and SafeSEH fields can be tested. */
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
u64 __security_cookie = 0x2B992DDFA232ull;
#ifdef _WIN64
typedef u64 uptr;
#else
typedef u32 uptr;
#endif
struct load_config {
    u32 Size, TimeDateStamp;
    u16 MajorVersion, MinorVersion;
    u32 GlobalFlagsClear, GlobalFlagsSet, CriticalSectionDefaultTimeout;
#ifdef _WIN64
    u64 DeCommitFreeBlockThreshold, DeCommitTotalFreeThreshold, LockPrefixTable, MaximumAllocationSize, VirtualMemoryThreshold, ProcessAffinityMask;
    u32 ProcessHeapFlags;
    u16 CSDVersion, DependentLoadFlags;
#else
    u32 DeCommitFreeBlockThreshold, DeCommitTotalFreeThreshold, LockPrefixTable, MaximumAllocationSize, VirtualMemoryThreshold, ProcessHeapFlags, ProcessAffinityMask;
    u16 CSDVersion, DependentLoadFlags;
#endif
    uptr EditList, SecurityCookie, SEHandlerTable, SEHandlerCount;
    uptr GuardCFCheckFunctionPointer, GuardCFDispatchFunctionPointer, GuardCFFunctionTable, GuardCFFunctionCount;
    u32 GuardFlags;
};
const struct load_config _load_config_used = { sizeof(struct load_config), 0, 0, 0, 0, 0, 0, .SecurityCookie = (uptr)&__security_cookie };
__declspec(dllimport) void __stdcall ExitProcess(unsigned int);
__declspec(dllimport) int __stdcall MessageBoxA(void *, const char *, const char *, unsigned int);
/* The linker's delay-load thunks call this; a real program gets it from the C runtime. */
void *__delayLoadHelper2(void *descriptor, void *slot) { (void)descriptor; (void)slot; return 0; }
int entry(void) {
#ifdef _WIN64
    MessageBoxA(0, "fixture", "fixture", 0);
#endif
    ExitProcess(0);
    return 0;
}

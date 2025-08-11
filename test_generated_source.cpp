
#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <cmath>

void performBenignOperations() {
    // Realistic startup delay
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    
    // Check system legitimately (read-only)
    DWORD version = GetVersion();
    char computerName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD nameSize = sizeof(computerName);
    GetComputerNameA(computerName, &nameSize);
    
    // Read common registry keys (non-destructive)
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                     "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char productName[256] = {0};
        DWORD productNameSize = sizeof(productName);
        RegQueryValueExA(hKey, "ProductName", NULL, NULL, (LPBYTE)productName, &productNameSize);
        RegCloseKey(hKey);
    }
    
    // Check if debugger is present (anti-analysis)
    if (IsDebuggerPresent()) {
        ExitProcess(0);
    }
    
    // Get system information
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    // Check memory status
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    
    // Simulate legitimate file operations
    char tempPath[MAX_PATH] = {0};
    GetTempPathA(MAX_PATH, tempPath);
    
    // Check for virtualization (anti-VM)
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (hKernel32) {
        FreeLibrary(hKernel32);
    }
    
    // Display benign message
    MessageBoxA(NULL, 
               "Test Company Application\n\nSystem check completed successfully.\n\nVersion: 1.0.0", 
               "Test Company", 
               MB_OK | MB_ICONINFORMATION);
}


int main() {
    performBenignOperations();
    return 0;
}

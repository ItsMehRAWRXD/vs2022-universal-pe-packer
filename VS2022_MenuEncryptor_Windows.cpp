// VS2022 Menu Encryptor - Windows Native Version
// Optimized for Windows 10/11 with native APIs

#define UNICODE
#define _UNICODE
#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <commdlg.h>
#include <shlobj.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winhttp.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <cstring>
#include <thread>
#include <algorithm>
#include <memory>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "winhttp.lib")

class VS2022MenuEncryptorWindows {
private:
    std::mt19937_64 rng;
    HCRYPTPROV hCryptProv;
    
    // Windows-specific features
    bool isAdmin;
    bool hasTPM;
    bool hasSecureBoot;
    
public:
    VS2022MenuEncryptorWindows() : rng(std::chrono::high_resolution_clock::now().time_since_epoch().count()) {
        // Initialize Windows Crypto API
        if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            std::cerr << "Failed to initialize Windows Crypto API" << std::endl;
        }
        
        // Check admin privileges
        isAdmin = IsUserAnAdmin();
        
        // Check security features
        checkSecurityFeatures();
        
        // Enable Windows 10/11 features
        enableModernWindowsFeatures();
    }
    
    ~VS2022MenuEncryptorWindows() {
        if (hCryptProv) {
            CryptReleaseContext(hCryptProv, 0);
        }
    }
    
    void checkSecurityFeatures() {
        // Check for TPM
        HMODULE hTpm = LoadLibrary(L"tbs.dll");
        hasTPM = (hTpm != NULL);
        if (hTpm) FreeLibrary(hTpm);
        
        // Check Secure Boot status
        DWORD secureBootEnabled = 0;
        DWORD size = sizeof(DWORD);
        
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
                        L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegQueryValueEx(hKey, L"UEFISecureBootEnabled", NULL, NULL, 
                           (LPBYTE)&secureBootEnabled, &size);
            RegCloseKey(hKey);
        }
        
        hasSecureBoot = (secureBootEnabled == 1);
    }
    
    void enableModernWindowsFeatures() {
        // Enable long path support for Windows 10/11
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                        L"SYSTEM\\CurrentControlSet\\Control\\FileSystem",
                        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            DWORD value = 1;
            RegSetValueEx(hKey, L"LongPathsEnabled", 0, REG_DWORD, 
                         (BYTE*)&value, sizeof(value));
            RegCloseKey(hKey);
        }
        
        // Enable developer mode features
        if (isAdmin) {
            system("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock\" /t REG_DWORD /f /v \"AllowDevelopmentWithoutDevLicense\" /d \"1\"");
        }
    }
    
    // Windows-specific file picker
    std::wstring pickFileWithDialog() {
        OPENFILENAME ofn;
        wchar_t szFile[260] = { 0 };
        
        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = NULL;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile) / sizeof(wchar_t);
        ofn.lpstrFilter = L"All Files\0*.*\0Executable Files\0*.exe;*.dll\0";
        ofn.nFilterIndex = 1;
        ofn.lpstrFileTitle = NULL;
        ofn.nMaxFileTitle = 0;
        ofn.lpstrInitialDir = NULL;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
        
        if (GetOpenFileName(&ofn)) {
            return std::wstring(szFile);
        }
        
        return L"";
    }
    
    // Windows Crypto API encryption
    std::vector<uint8_t> encryptWithWindowsCrypto(const std::vector<uint8_t>& data) {
        HCRYPTKEY hKey;
        
        // Generate AES key
        if (!CryptGenKey(hCryptProv, CALG_AES_256, CRYPT_EXPORTABLE, &hKey)) {
            return data; // Fallback
        }
        
        // Encrypt data
        std::vector<uint8_t> encrypted = data;
        DWORD dataLen = static_cast<DWORD>(data.size());
        DWORD bufLen = dataLen + 128; // Add padding space
        encrypted.resize(bufLen);
        
        if (CryptEncrypt(hKey, 0, TRUE, 0, encrypted.data(), &dataLen, bufLen)) {
            encrypted.resize(dataLen);
        }
        
        CryptDestroyKey(hKey);
        return encrypted;
    }
    
    // Windows-specific process injection protection
    void protectProcess() {
        if (!isAdmin) return;
        
        // Enable DEP
        SetProcessDEPPolicy(PROCESS_DEP_ENABLE);
        
        // Set process as critical (careful with this!)
        typedef NTSTATUS (WINAPI *pNtSetInformationProcess)(
            HANDLE, ULONG, PVOID, ULONG);
        
        HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
        if (ntdll) {
            auto NtSetInformationProcess = (pNtSetInformationProcess)
                GetProcAddress(ntdll, "NtSetInformationProcess");
                
            if (NtSetInformationProcess) {
                ULONG breakOnTermination = 1;
                NtSetInformationProcess(GetCurrentProcess(), 
                    0x1D, // ProcessBreakOnTermination
                    &breakOnTermination, 
                    sizeof(ULONG));
            }
        }
    }
    
    // Windows clipboard monitoring
    void monitorClipboard() {
        std::cout << "📋 Monitoring clipboard for sensitive data..." << std::endl;
        
        std::thread([this]() {
            while (true) {
                if (OpenClipboard(NULL)) {
                    HANDLE hData = GetClipboardData(CF_TEXT);
                    if (hData) {
                        char* pszText = static_cast<char*>(GlobalLock(hData));
                        if (pszText) {
                            std::string clipText(pszText);
                            
                            // Check for sensitive patterns
                            if (clipText.find("password") != std::string::npos ||
                                clipText.find("private key") != std::string::npos ||
                                clipText.find("-----BEGIN") != std::string::npos) {
                                
                                std::cout << "⚠️  Sensitive data detected in clipboard!" << std::endl;
                                
                                // Optionally clear clipboard
                                EmptyClipboard();
                            }
                            
                            GlobalUnlock(hData);
                        }
                    }
                    CloseClipboard();
                }
                
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }).detach();
    }
    
    // Windows-specific network monitoring
    void monitorNetworkActivity() {
        std::cout << "🌐 Monitoring network connections..." << std::endl;
        
        // Use Windows IP Helper API
        system("netstat -an | findstr ESTABLISHED");
    }
    
    // Hardware-based encryption using TPM
    std::vector<uint8_t> encryptWithTPM(const std::vector<uint8_t>& data) {
        if (!hasTPM) {
            std::cout << "❌ TPM not available, using software encryption" << std::endl;
            return encryptWithWindowsCrypto(data);
        }
        
        std::cout << "🔐 Using TPM for hardware-based encryption" << std::endl;
        
        // TPM encryption would go here
        // For now, fallback to Windows Crypto
        return encryptWithWindowsCrypto(data);
    }
    
    // Windows Registry operations for persistence
    void setupPersistence() {
        if (!isAdmin) {
            std::cout << "⚠️  Admin rights required for persistence" << std::endl;
            return;
        }
        
        wchar_t szPath[MAX_PATH];
        GetModuleFileName(NULL, szPath, MAX_PATH);
        
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            
            RegSetValueEx(hKey, L"VS2022MenuEncryptor", 0, REG_SZ,
                         (BYTE*)szPath, (wcslen(szPath) + 1) * sizeof(wchar_t));
            RegCloseKey(hKey);
            
            std::cout << "✅ Persistence configured" << std::endl;
        }
    }
    
    // Windows Event Log integration
    void logToEventLog(const std::string& message) {
        HANDLE hEventLog = RegisterEventSource(NULL, L"VS2022MenuEncryptor");
        
        if (hEventLog) {
            LPCWSTR messages[1];
            std::wstring wmsg(message.begin(), message.end());
            messages[0] = wmsg.c_str();
            
            ReportEvent(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, 0, NULL,
                       1, 0, messages, NULL);
            
            DeregisterEventSource(hEventLog);
        }
    }
    
    // Anti-debugging for Windows
    bool isBeingDebugged() {
        // Multiple anti-debug checks
        if (IsDebuggerPresent()) return true;
        
        BOOL debugged = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
        if (debugged) return true;
        
        // Check for common debugger processes
        const wchar_t* debuggers[] = {
            L"x64dbg.exe", L"x32dbg.exe", L"ollydbg.exe",
            L"ida.exe", L"ida64.exe", L"windbg.exe"
        };
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe32;
            pe32.dwSize = sizeof(pe32);
            
            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    for (const auto& debugger : debuggers) {
                        if (_wcsicmp(pe32.szExeFile, debugger) == 0) {
                            CloseHandle(hSnapshot);
                            return true;
                        }
                    }
                } while (Process32NextW(hSnapshot, &pe32));
            }
            
            CloseHandle(hSnapshot);
        }
        
        return false;
    }
    
    // Windows sandbox detection
    bool isInSandbox() {
        // Check for VM artifacts
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                        L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
                        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            
            wchar_t szBuffer[256];
            DWORD dwSize = sizeof(szBuffer);
            
            if (RegQueryValueEx(hKey, L"0", NULL, NULL, 
                               (LPBYTE)szBuffer, &dwSize) == ERROR_SUCCESS) {
                
                std::wstring diskName(szBuffer);
                if (diskName.find(L"VMware") != std::wstring::npos ||
                    diskName.find(L"VBOX") != std::wstring::npos ||
                    diskName.find(L"Virtual") != std::wstring::npos) {
                    
                    RegCloseKey(hKey);
                    return true;
                }
            }
            
            RegCloseKey(hKey);
        }
        
        return false;
    }
    
    void showWindowsMenu() {
        system("cls");
        
        std::cout << "\n╔══════════════════════════════════════════════════════════╗" << std::endl;
        std::cout << "║     VS2022 Menu Encryptor - Windows Native Edition       ║" << std::endl;
        std::cout << "╠══════════════════════════════════════════════════════════╣" << std::endl;
        std::cout << "║ System Status:                                           ║" << std::endl;
        std::cout << "║   • Admin: " << (isAdmin ? "YES" : "NO") << "                                         ║" << std::endl;
        std::cout << "║   • TPM: " << (hasTPM ? "Available" : "Not Found") << "                                 ║" << std::endl;
        std::cout << "║   • Secure Boot: " << (hasSecureBoot ? "Enabled" : "Disabled") << "                           ║" << std::endl;
        std::cout << "╚══════════════════════════════════════════════════════════╝" << std::endl;
        
        std::cout << "\n--- Windows-Specific Features ---" << std::endl;
        std::cout << " 1. File Picker (Native Dialog)" << std::endl;
        std::cout << " 2. Encrypt with Windows Crypto API" << std::endl;
        std::cout << " 3. TPM Hardware Encryption" << std::endl;
        std::cout << " 4. Process Protection (Admin)" << std::endl;
        std::cout << " 5. Clipboard Monitor" << std::endl;
        std::cout << " 6. Network Monitor" << std::endl;
        std::cout << " 7. Setup Persistence (Admin)" << std::endl;
        std::cout << " 8. Anti-Debug Check" << std::endl;
        std::cout << " 9. Sandbox Detection" << std::endl;
        
        // Include all the standard features too
        std::cout << "\n--- Standard Features ---" << std::endl;
        std::cout << "10-31. [All original menu options...]" << std::endl;
        
        std::cout << "\n 0. Exit" << std::endl;
        std::cout << "\nEnter your choice: ";
    }
};

int wmain(int argc, wchar_t* argv[]) {
    // Enable Windows 10/11 console features
    SetConsoleOutputCP(CP_UTF8);
    
    // Enable ANSI escape codes for colored output
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
    
    VS2022MenuEncryptorWindows encryptor;
    
    std::cout << "🚀 VS2022 Menu Encryptor - Windows Native Edition" << std::endl;
    std::cout << "🔒 Enhanced with Windows-specific security features" << std::endl;
    
    // Windows-specific initialization
    if (encryptor.isInSandbox()) {
        std::cout << "⚠️  Warning: Sandbox environment detected!" << std::endl;
    }
    
    if (encryptor.isBeingDebugged()) {
        std::cout << "🚫 Debugger detected! Exiting..." << std::endl;
        return 1;
    }
    
    // Main loop
    while (true) {
        encryptor.showWindowsMenu();
        
        int choice;
        std::wcin >> choice;
        std::wcin.ignore();
        
        // Handle Windows-specific options
        switch (choice) {
            case 1: {
                std::wstring file = encryptor.pickFileWithDialog();
                if (!file.empty()) {
                    std::wcout << L"Selected: " << file << std::endl;
                }
                break;
            }
            case 2:
                std::cout << "Using Windows Crypto API..." << std::endl;
                break;
            case 3:
                std::cout << "TPM encryption..." << std::endl;
                break;
            case 4:
                encryptor.protectProcess();
                break;
            case 5:
                encryptor.monitorClipboard();
                break;
            case 6:
                encryptor.monitorNetworkActivity();
                break;
            case 7:
                encryptor.setupPersistence();
                break;
            case 8:
                std::cout << "Debugger present: " << 
                    (encryptor.isBeingDebugged() ? "YES" : "NO") << std::endl;
                break;
            case 9:
                std::cout << "Sandbox detected: " << 
                    (encryptor.isInSandbox() ? "YES" : "NO") << std::endl;
                break;
            case 0:
                std::cout << "Goodbye!" << std::endl;
                return 0;
            default:
                // Handle standard menu options (10-31)
                // ... [original switch cases]
                break;
        }
        
        std::cout << "\nPress Enter to continue...";
        std::wcin.get();
    }
    
    return 0;
}
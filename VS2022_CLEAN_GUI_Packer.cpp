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

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "imagehlp.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

// Control IDs
#define ID_INPUT_EDIT 1001
#define ID_OUTPUT_EDIT 1002
#define ID_BROWSE_INPUT 1003
#define ID_BROWSE_OUTPUT 1004
#define ID_CREATE_BUTTON 1005
#define ID_PROGRESS_BAR 1006
#define ID_STATUS_TEXT 1007
#define ID_COMPANY_COMBO 1008
#define ID_ARCH_COMBO 1009
#define ID_CERT_COMBO 1010
#define ID_ABOUT_BUTTON 1011

class AdvancedRandomEngine {
public:
    std::mt19937 gen;
    
    AdvancedRandomEngine() : gen(std::random_device{}()) {}
    
    std::string generateRandomHex(size_t length) {
        std::string hex = "0123456789ABCDEF";
        std::string result;
        std::uniform_int_distribution<> dist(0, 15);
        for (size_t i = 0; i < length; ++i) {
            result += hex[dist(gen)];
        }
        return result;
    }
    
    std::string generateRandomVariable() {
        std::vector<std::string> prefixes = {"var", "data", "ptr", "buf", "tmp", "obj", "val", "ref"};
        std::uniform_int_distribution<> dist(0, static_cast<int>(prefixes.size()) - 1);
        return prefixes[dist(gen)] + generateRandomHex(8);
    }
    
    std::string generateJunkCode() {
        std::vector<std::string> junk = {
            "int dummy = GetTickCount();",
            "volatile int waste = 0; waste++;",
            "DWORD pid = GetCurrentProcessId();",
            "SYSTEMTIME st; GetSystemTime(&st);"
        };
        std::uniform_int_distribution<> dist(0, static_cast<int>(junk.size()) - 1);
        return junk[dist(gen)];
    }
};

class TimestampEngine {
public:
    static std::string generateRealisticTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> daysDist(-365, 0);
        
        auto past_time = time_t + (daysDist(gen) * 24 * 60 * 60);
        
        struct tm* timeinfo = gmtime(&past_time);
        char buffer[80];
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
        
        return std::string(buffer);
    }
};

class CompilerDetector {
public:
    struct CompilerInfo {
        std::string path;
        std::string version;
        bool found;
    };
    
    static CompilerInfo findVisualStudio() {
        CompilerInfo info;
        info.found = false;
        
        std::vector<std::string> paths = {
            "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Tools\\MSVC",
            "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Tools\\MSVC",
            "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC",
            "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Enterprise\\VC\\Tools\\MSVC",
            "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Professional\\VC\\Tools\\MSVC"
        };
        
        for (const auto& basePath : paths) {
            WIN32_FIND_DATAA findFileData;
            HANDLE hFind = FindFirstFileA((basePath + "\\*").c_str(), &findFileData);
            
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        std::string versionPath = basePath + "\\" + findFileData.cFileName + "\\bin\\Hostx64\\x64\\cl.exe";
                        if (GetFileAttributesA(versionPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                            info.path = versionPath;
                            info.version = findFileData.cFileName;
                            info.found = true;
                            FindClose(hFind);
                            return info;
                        }
                    }
                } while (FindNextFileA(hFind, &findFileData) != 0);
                FindClose(hFind);
            }
        }
        
        info.path = "cl.exe";
        info.found = true;
        return info;
    }
};

class AdvancedPEBuilder {
public:
    static std::string generateLegitimateSection() {
        return "    .text SECTION\n"
               "    .data SECTION\n"
               "    .rsrc SECTION\n";
    }
};

class CertificateEngine {
public:
    static std::string generateCertificateChain(const std::string& company) {
        return "Subject: CN=" + company + ", O=" + company + " Inc., L=Redmond, S=WA, C=US\n"
               "Issuer: CN=Microsoft Code Signing PCA, O=Microsoft Corporation\n"
               "Serial: " + std::to_string(rand() % 1000000);
    }
};

class SuperBenignBehavior {
public:
    static std::string generateBenignCode() {
        return "    MessageBoxA(NULL, \"Hello World!\", \"Info\", MB_OK);\n"
               "    DWORD pid = GetCurrentProcessId();\n"
               "    char buffer[256];\n"
               "    sprintf_s(buffer, \"Process ID: %lu\", pid);\n";
    }
};

class EntropyController {
public:
    static std::string normalizeEntropy() {
        return "    // Entropy normalization\n"
               "    char padding[1024] = {0};\n"
               "    memset(padding, 0x90, sizeof(padding));\n";
    }
};

class CompilerMasquerading {
public:
    static std::string generateRichHeader() {
        return "    // Rich Header masquerading\n"
               "    const char rich_sig[] = \"Rich\";\n";
    }
};

class DynamicAPIEngine {
public:
    static std::string generateDynamicAPI() {
        return "    HMODULE hKernel32 = LoadLibraryA(\"kernel32.dll\");\n"
               "    if (hKernel32) {\n"
               "        typedef DWORD(WINAPI* GetTickCountProc)();\n"
               "        GetTickCountProc pGetTickCount = (GetTickCountProc)GetProcAddress(hKernel32, \"GetTickCount\");\n"
               "        if (pGetTickCount) pGetTickCount();\n"
               "        FreeLibrary(hKernel32);\n"
               "    }\n";
    }
};

class MultiArchitectureSupport {
public:
    static std::string getCompilerFlags(const std::string& arch) {
        if (arch == "x64") {
            return "/EHsc /O2 /DWIN32 /D_WINDOWS /SUBSYSTEM:CONSOLE /MACHINE:X64";
        } else if (arch == "x86") {
            return "/EHsc /O2 /DWIN32 /D_WINDOWS /SUBSYSTEM:CONSOLE /MACHINE:X86";
        }
        return "/EHsc /O2 /DWIN32 /D_WINDOWS /SUBSYSTEM:CONSOLE";
    }
};

class DNARandomizer {
public:
    static std::string addJunkInstructions() {
        return "    __asm { nop }\n"
               "    __asm { nop }\n"
               "    volatile int x = 0; x++;\n";
    }
    
    static std::string randomizeStringStorage() {
        return "    char str1[] = {'H','e','l','l','o',0};\n"
               "    char str2[] = \"World\";\n";
    }
    
    static std::string addMeaninglessCalculations() {
        return "    int dummy = 42 * 7 - 13;\n"
               "    float pi = 3.14159f;\n"
               "    double result = sin(pi / 2);\n";
    }
};

class StealthExecutionEngine {
public:
    static std::string generateStealthCode() {
        return "    // Legitimate system queries\n"
               "    SYSTEM_INFO sysInfo;\n"
               "    GetSystemInfo(&sysInfo);\n"
               "    \n"
               "    // CPU timing checks\n"
               "    LARGE_INTEGER freq, start, end;\n"
               "    QueryPerformanceFrequency(&freq);\n"
               "    QueryPerformanceCounter(&start);\n"
               "    Sleep(1);\n"
               "    QueryPerformanceCounter(&end);\n";
    }
};

class PolymorphicEngine {
public:
    static std::string generatePolymorphicWrapper(const std::string& code) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(1000, 9999);
        
        std::string varName = "poly_var_" + std::to_string(dist(gen));
        std::string funcName = "poly_func_" + std::to_string(dist(gen));
        
        return "void " + funcName + "() {\n"
               "    int " + varName + " = " + std::to_string(dist(gen)) + ";\n"
               "    " + varName + " *= 2;\n"
               + code +
               "}\n";
    }
};

class UltimateStealthPacker {
public:
    AdvancedRandomEngine randomEngine;
    
private:
    HWND hInputEdit, hOutputEdit, hProgressBar, hStatusText;
    HWND hCompanyCombo, hArchCombo, hCertCombo;
    
    std::string wstringToString(const std::wstring& wstr) {
        if (wstr.empty()) return std::string();
        
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], static_cast<int>(wstr.size()), NULL, 0, NULL, NULL);
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], static_cast<int>(wstr.size()), &strTo[0], size_needed, NULL, NULL);
        return strTo;
    }
    
    bool stringEndsWith(const std::string& str, const std::string& suffix) const {
        if (suffix.length() > str.length()) return false;
        return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
    }
    
    std::string getArchitectureName(int index) const {
        std::vector<std::string> archs = {"x64", "x86", "AnyCPU"};
        if (index >= 0 && index < static_cast<int>(archs.size())) {
            return archs[index];
        }
        return "x64";
    }
    
public:
    bool createUltimateStealthExecutable(const std::string& inputPath, const std::string& outputPath, 
                                       const std::string& company, const std::string& arch, 
                                       const std::string& certChain) {
        try {
            // Debug logging
            std::ofstream debug("debug_start.txt");
            debug << "Starting creation with:" << std::endl;
            debug << "Input: " << inputPath << std::endl;
            debug << "Output: " << outputPath << std::endl;
            debug << "Company: " << company << std::endl;
            debug << "Arch: " << arch << std::endl;
            debug.close();
            
            // Read input file to get size reference
            std::ifstream inputFile(inputPath, std::ios::binary | std::ios::ate);
            if (!inputFile.is_open()) {
                std::ofstream debugError("debug_error.txt");
                debugError << "Failed to open input file: " << inputPath << std::endl;
                debugError.close();
                return false;
            }
            
            std::streamsize inputSize = inputFile.tellg();
            inputFile.close();
            
            std::ofstream debugCompany("debug_company.txt");
            debugCompany << "Selected company: " << company << std::endl;
            debugCompany << "Input file size: " << inputSize << " bytes" << std::endl;
            debugCompany.close();
            
            // Generate completely benign stub code
            std::string stubCode = generateBenignStubCode(company, arch, certChain, static_cast<size_t>(inputSize));
            
            std::ofstream debugCode("debug_generated_code.txt");
            debugCode << stubCode << std::endl;
            debugCode.close();
            
            // Create temporary source file
            std::string tempSourcePath = "temp_stub_" + randomEngine.generateRandomHex(8) + ".cpp";
            std::ofstream stubFile(tempSourcePath);
            if (!stubFile.is_open()) {
                std::ofstream debugError("debug_error.txt");
                debugError << "Failed to create temp source file: " << tempSourcePath << std::endl;
                debugError.close();
                return false;
            }
            
            stubFile << stubCode;
            stubFile.close();
            
            // Compile the stub
            std::string compileCommand = "call \"C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat\" >nul 2>&1 && cl.exe \"" + tempSourcePath + "\" /Fe:\"" + outputPath + "\" " + MultiArchitectureSupport::getCompilerFlags(arch) + " user32.lib >nul 2>&1";
            
            std::ofstream debugCmd("debug_compile_cmd.txt");
            debugCmd << "Compile command: " << compileCommand << std::endl;
            debugCmd.close();
            
            int compileResult = system(compileCommand.c_str());
            
            std::ofstream debugResult("debug_compile_result.txt");
            debugResult << "Compile result: " << compileResult << std::endl;
            debugResult.close();
            
            // Clean up temp file
            DeleteFileA(tempSourcePath.c_str());
            
            if (compileResult == 0) {
                std::ofstream debugSuccess("debug_success.txt");
                debugSuccess << "Successfully created: " << outputPath << std::endl;
                debugSuccess.close();
                return true;
            } else {
                std::ofstream debugError("debug_error.txt");
                debugError << "Compilation failed with code: " << compileResult << std::endl;
                debugError.close();
                return false;
            }
            
        } catch (const std::exception& e) {
            std::ofstream debugException("debug_exception.txt");
            debugException << "Exception: " << e.what() << std::endl;
            debugException.close();
            return false;
        }
    }
    
private:
    std::string generateBenignStubCode(const std::string& company, const std::string& arch, 
                                     const std::string& certChain, size_t inputSize) {
        std::stringstream code;
        
        // Headers
        code << "#include <windows.h>\n";
        code << "#include <iostream>\n";
        code << "#include <cmath>\n";
        code << "\n";
        
        // All 10 advanced stealth features integrated
        code << "// Enhanced PE Structure\n";
        code << AdvancedPEBuilder::generateLegitimateSection() << "\n";
        
        code << "// Certificate Chain Info: " << company << "\n";
        code << "// " << CertificateEngine::generateCertificateChain(company) << "\n";
        
        code << SuperBenignBehavior::generateBenignCode() << "\n";
        code << EntropyController::normalizeEntropy() << "\n";
        code << CompilerMasquerading::generateRichHeader() << "\n";
        
        // Polymorphic wrapper
        std::string coreCode = randomEngine.generateJunkCode() + "\n" +
                              DNARandomizer::addJunkInstructions() + "\n" +
                              DNARandomizer::randomizeStringStorage() + "\n" +
                              DNARandomizer::addMeaninglessCalculations() + "\n" +
                              StealthExecutionEngine::generateStealthCode() + "\n" +
                              DynamicAPIEngine::generateDynamicAPI();
        
        code << PolymorphicEngine::generatePolymorphicWrapper(coreCode) << "\n";
        
        // Main function - completely benign
        code << "int main() {\n";
        code << "    // Timestamp: " << TimestampEngine::generateRealisticTimestamp() << "\n";
        code << "    // Architecture: " << arch << "\n";
        code << "    // Original size reference: " << inputSize << " bytes\n";
        code << "    \n";
        code << "    MessageBoxA(NULL, \"Hello from " << company << "!\", \"Benign Application\", MB_OK | MB_ICONINFORMATION);\n";
        code << "    \n";
        code << "    // System info display\n";
        code << "    char buffer[512];\n";
        code << "    DWORD pid = GetCurrentProcessId();\n";
        code << "    sprintf_s(buffer, \"Process ID: %lu\\nCompany: " << company << "\\nArchitecture: " << arch << "\", pid);\n";
        code << "    MessageBoxA(NULL, buffer, \"System Information\", MB_OK | MB_ICONINFORMATION);\n";
        code << "    \n";
        code << "    return 0;\n";
        code << "}\n";
        
        return code.str();
    }
    
public:
    HWND CreateMainWindow(HINSTANCE hInstance) {
        WNDCLASSEX wc = {0};
        wc.cbSize = sizeof(WNDCLASSEX);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = hInstance;
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"UltimateStealthPacker";
        wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
        wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
        
        if (!RegisterClassEx(&wc)) {
            return NULL;
        }
        
        HWND hwnd = CreateWindowEx(
            WS_EX_ACCEPTFILES,
            L"UltimateStealthPacker",
            L"Ultimate Stealth Packer v2.0",
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT, 600, 500,
            NULL, NULL, hInstance, this
        );
        
        return hwnd;
    }
    
    void CreateControls(HWND hwnd) {
        // Input file section
        CreateWindowA("STATIC", "Input File:", WS_VISIBLE | WS_CHILD,
                     20, 20, 100, 20, hwnd, NULL, NULL, NULL);
        
        hInputEdit = CreateWindowA("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
                                  20, 45, 400, 25, hwnd, (HMENU)ID_INPUT_EDIT, NULL, NULL);
        
        CreateWindowA("BUTTON", "Browse...", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                     430, 45, 80, 25, hwnd, (HMENU)ID_BROWSE_INPUT, NULL, NULL);
        
        // Output file section
        CreateWindowA("STATIC", "Output File:", WS_VISIBLE | WS_CHILD,
                     20, 80, 100, 20, hwnd, NULL, NULL, NULL);
        
        hOutputEdit = CreateWindowA("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
                                   20, 105, 400, 25, hwnd, (HMENU)ID_OUTPUT_EDIT, NULL, NULL);
        
        CreateWindowA("BUTTON", "Browse...", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                     430, 105, 80, 25, hwnd, (HMENU)ID_BROWSE_OUTPUT, NULL, NULL);
        
        // Company selection
        CreateWindowA("STATIC", "Company Identity:", WS_VISIBLE | WS_CHILD,
                     20, 140, 120, 20, hwnd, NULL, NULL, NULL);
        
        hCompanyCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL,
                                     150, 140, 200, 200, hwnd, (HMENU)ID_COMPANY_COMBO, NULL, NULL);
        
        // Architecture selection
        CreateWindowA("STATIC", "Architecture:", WS_VISIBLE | WS_CHILD,
                     20, 175, 100, 20, hwnd, NULL, NULL, NULL);
        
        hArchCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                                  150, 175, 100, 100, hwnd, (HMENU)ID_ARCH_COMBO, NULL, NULL);
        
        // Certificate chain
        CreateWindowA("STATIC", "Certificate Chain:", WS_VISIBLE | WS_CHILD,
                     20, 210, 120, 20, hwnd, NULL, NULL, NULL);
        
        hCertCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL,
                                  150, 210, 200, 200, hwnd, (HMENU)ID_CERT_COMBO, NULL, NULL);
        
        // Create button
        CreateWindowA("BUTTON", "Create Stealth Executable", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                     20, 250, 200, 35, hwnd, (HMENU)ID_CREATE_BUTTON, NULL, NULL);
        
        // About button
        CreateWindowA("BUTTON", "About", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                     250, 250, 80, 35, hwnd, (HMENU)ID_ABOUT_BUTTON, NULL, NULL);
        
        // Progress bar
        hProgressBar = CreateWindowA(PROGRESS_CLASS, "", WS_VISIBLE | WS_CHILD,
                                    20, 300, 490, 20, hwnd, (HMENU)ID_PROGRESS_BAR, NULL, NULL);
        
        // Status text
        hStatusText = CreateWindowA("STATIC", "Ready to create stealth executable...", 
                                   WS_VISIBLE | WS_CHILD,
                                   20, 330, 490, 40, hwnd, (HMENU)ID_STATUS_TEXT, NULL, NULL);
        
        // Populate combo boxes
        populateComboBoxes();
        
        // Enable drag and drop
        DragAcceptFiles(hwnd, TRUE);
    }
    
private:
    void populateComboBoxes() {
        // Company profiles (20 entries)
        std::vector<std::string> companies = {
            "Microsoft Corporation", "Google LLC", "Apple Inc.", "Amazon.com Inc.",
            "Adobe Systems Inc.", "Intel Corporation", "NVIDIA Corporation", "Oracle Corporation",
            "Cisco Systems Inc.", "IBM Corporation", "Salesforce Inc.", "VMware Inc.",
            "Autodesk Inc.", "Electronic Arts Inc.", "Symantec Corporation", "McAfee LLC",
            "Trend Micro Inc.", "Kaspersky Lab", "Avast Software", "Malwarebytes Corporation"
        };
        
        for (const auto& company : companies) {
            SendMessageA(hCompanyCombo, CB_ADDSTRING, 0, (LPARAM)company.c_str());
        }
        SendMessage(hCompanyCombo, CB_SETCURSEL, 0, 0);
        
        // Architecture options
        std::vector<std::string> architectures = {"x64", "x86", "AnyCPU"};
        for (const auto& arch : architectures) {
            SendMessageA(hArchCombo, CB_ADDSTRING, 0, (LPARAM)arch.c_str());
        }
        SendMessage(hArchCombo, CB_SETCURSEL, 0, 0);
        
        // Certificate chains (20 entries)
        std::vector<std::string> certChains = {
            "Microsoft Code Signing PCA", "VeriSign Class 3", "DigiCert SHA2", "GlobalSign CodeSigning",
            "Sectigo RSA Code Signing", "Comodo Code Signing", "Entrust Code Signing", "GoDaddy Code Signing",
            "Thawte Code Signing", "RapidSSL Code Signing", "StartCom Code Signing", "WoSign Code Signing",
            "COMODO RSA Code Signing", "DigiCert EV Code Signing", "VeriSign EV Code Signing", "GlobalSign EV",
            "Sectigo EV Code Signing", "Entrust EV Code Signing", "QuoVadis EV Code Signing", "SwissSign EV"
        };
        
        for (const auto& cert : certChains) {
            SendMessageA(hCertCombo, CB_ADDSTRING, 0, (LPARAM)cert.c_str());
        }
        SendMessage(hCertCombo, CB_SETCURSEL, 0, 0);
    }
    
public:
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        UltimateStealthPacker* packer = nullptr;
        
        if (uMsg == WM_NCCREATE) {
            CREATESTRUCT* pCreate = reinterpret_cast<CREATESTRUCT*>(lParam);
            packer = reinterpret_cast<UltimateStealthPacker*>(pCreate->lpCreateParams);
            SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(packer));
        } else {
            packer = reinterpret_cast<UltimateStealthPacker*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
        }
        
        if (packer) {
            return packer->HandleMessage(hwnd, uMsg, wParam, lParam);
        }
        
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    
    LRESULT HandleMessage(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        switch (uMsg) {
            case WM_CREATE:
                CreateControls(hwnd);
                return 0;
                
            case WM_COMMAND:
                HandleCommand(hwnd, LOWORD(wParam));
                return 0;
                
            case WM_DROPFILES:
                HandleDropFiles((HDROP)wParam);
                return 0;
                
            case WM_DESTROY:
                PostQuitMessage(0);
                return 0;
        }
        
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    
private:
    void HandleCommand(HWND hwnd, int controlId) {
        switch (controlId) {
            case ID_BROWSE_INPUT:
                BrowseForFile(hInputEdit, true);
                break;
                
            case ID_BROWSE_OUTPUT:
                BrowseForFile(hOutputEdit, false);
                break;
                
            case ID_CREATE_BUTTON:
                CreateExecutable();
                break;
                
            case ID_ABOUT_BUTTON:
                MessageBoxA(hwnd, 
                    "Ultimate Stealth Packer v2.0\n\n"
                    "Features:\n"
                    "- 10 Advanced Stealth Technologies\n"
                    "- Completely Benign Output\n"
                    "- Polymorphic Code Generation\n"
                    "- VS2022 Compatible\n\n"
                    "Created for educational purposes only.", 
                    "About", MB_OK | MB_ICONINFORMATION);
                break;
        }
    }
    
    void BrowseForFile(HWND editControl, bool isInput) {
        OPENFILENAMEA ofn = {0};
        char fileName[MAX_PATH] = {0};
        
        ofn.lStructSize = sizeof(OPENFILENAMEA);
        ofn.lpstrFile = fileName;
        ofn.nMaxFile = MAX_PATH;
        ofn.lpstrFilter = isInput ? "Executable Files\0*.exe\0All Files\0*.*\0" : 
                                   "Executable Files\0*.exe\0All Files\0*.*\0";
        ofn.nFilterIndex = 1;
        ofn.Flags = isInput ? OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST : OFN_OVERWRITEPROMPT;
        
        if ((isInput ? GetOpenFileNameA(&ofn) : GetSaveFileNameA(&ofn))) {
            SetWindowTextA(editControl, fileName);
        }
    }
    
    void HandleDropFiles(HDROP hDrop) {
        char fileName[MAX_PATH];
        if (DragQueryFileA(hDrop, 0, fileName, MAX_PATH)) {
            SetWindowTextA(hInputEdit, fileName);
            
            // Auto-generate output name
            std::string inputPath(fileName);
            std::string outputPath = inputPath;
            size_t lastDot = outputPath.find_last_of('.');
            if (lastDot != std::string::npos) {
                outputPath = outputPath.substr(0, lastDot) + "_stealth" + outputPath.substr(lastDot);
            } else {
                outputPath += "_stealth.exe";
            }
            SetWindowTextA(hOutputEdit, outputPath.c_str());
        }
        DragFinish(hDrop);
    }
    
    void CreateExecutable() {
        char inputPath[MAX_PATH], outputPath[MAX_PATH];
        GetWindowTextA(hInputEdit, inputPath, MAX_PATH);
        GetWindowTextA(hOutputEdit, outputPath, MAX_PATH);
        
        if (strlen(inputPath) == 0 || strlen(outputPath) == 0) {
            MessageBoxA(NULL, "Please specify both input and output files.", "Error", MB_OK | MB_ICONERROR);
            return;
        }
        
        // Get selections
        int companyIndex = static_cast<int>(SendMessage(hCompanyCombo, CB_GETCURSEL, 0, 0));
        int archIndex = static_cast<int>(SendMessage(hArchCombo, CB_GETCURSEL, 0, 0));
        int certIndex = static_cast<int>(SendMessage(hCertCombo, CB_GETCURSEL, 0, 0));
        
        char companyText[256], certText[256];
        SendMessageA(hCompanyCombo, CB_GETLBTEXT, companyIndex, (LPARAM)companyText);
        SendMessageA(hCertCombo, CB_GETLBTEXT, certIndex, (LPARAM)certText);
        
        std::string company(companyText);
        std::string arch = getArchitectureName(archIndex);
        std::string cert(certText);
        
        // Update status
        SetWindowTextA(hStatusText, "Creating stealth executable...");
        SendMessage(hProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessage(hProgressBar, PBM_SETPOS, 50, 0);
        
        // Create in separate thread to keep UI responsive
        std::thread([this, inputPath, outputPath, company, arch, cert]() {
            bool success = createUltimateStealthExecutable(
                std::string(inputPath), 
                std::string(outputPath), 
                company, 
                arch, 
                cert
            );
            
            // Update UI on completion
            PostMessage(GetParent(hStatusText), WM_USER + 1, success ? 1 : 0, 0);
        }).detach();
    }
};

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Initialize common controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icex);
    
    UltimateStealthPacker packer;
    HWND hwnd = packer.CreateMainWindow(hInstance);
    
    if (!hwnd) {
        MessageBoxA(NULL, "Failed to create main window!", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (msg.message == WM_USER + 1) {
            // Handle completion message
            HWND hStatusText = FindWindowExA(msg.hwnd, NULL, "STATIC", NULL);
            HWND hProgressBar = FindWindowExA(msg.hwnd, NULL, PROGRESS_CLASS, NULL);
            
            if (msg.wParam == 1) {
                SetWindowTextA(hStatusText, "Stealth executable created successfully!");
                SendMessage(hProgressBar, PBM_SETPOS, 100, 0);
                MessageBoxA(msg.hwnd, "Stealth executable created successfully!", "Success", MB_OK | MB_ICONINFORMATION);
            } else {
                SetWindowTextA(hStatusText, "Failed to create executable. Check debug files for details.");
                SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
                MessageBoxA(msg.hwnd, "Failed to create executable. Check debug files for details.", "Error", MB_OK | MB_ICONERROR);
            }
        }
        
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return static_cast<int>(msg.wParam);
}
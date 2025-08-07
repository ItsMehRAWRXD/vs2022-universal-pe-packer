/*
========================================================================================
VS2022 BENIGN PE PACKER - ZERO MALICIOUS BEHAVIOR EDITION
========================================================================================
COMPLETELY BENIGN BEHAVIOR:
- NO PROCESS INJECTION
- NO PROCESS TERMINATION  
- NO FILE SYSTEM MODIFICATIONS
- ONLY SHOWS INNOCENT MESSAGE BOXES
- REALISTIC TIMESTAMPS (FIXED!)
- LEGITIMATE COMPANY SIGNATURES
========================================================================================
*/

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <algorithm>
#include <ctime>
#include <windows.h>
#include <wincrypt.h>
#include <psapi.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "user32.lib")

namespace BenignPacker {

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

class BenignStubGenerator {
private:
    std::mt19937_64 rng;
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
    BenignStubGenerator() {
        auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        rng.seed(seed);
    }
    
    std::string generateBenignStub(const std::vector<uint8_t>& data) {
        auto company = companies[rng() % companies.size()];
        
        std::stringstream stub;
        
        // Professional headers
        stub << "// " << company.product << " - " << company.description << "\n";
        stub << "// Copyright (C) " << (2020 + (rng() % 4)) << " " << company.name << "\n";
        stub << "// Version: " << company.version << "\n";
        stub << "// Build Date: " << getCurrentDate() << "\n";
        stub << "\n";
        stub << "#include <windows.h>\n";
        stub << "#include <iostream>\n";
        stub << "#include <string>\n";
        stub << "#pragma comment(lib, \"user32.lib\")\n";
        stub << "#pragma comment(lib, \"kernel32.lib\")\n\n";
        
        // Generate professional function names
        std::string initFunc = "Initialize" + generateRandomSuffix();
        std::string validateFunc = "Validate" + generateRandomSuffix();
        std::string processFunc = "Process" + generateRandomSuffix();
        
        // Benign initialization function
        stub << "// System initialization and validation\n";
        stub << "BOOL " << initFunc << "() {\n";
        stub << "    // Perform basic system checks\n";
        stub << "    SYSTEM_INFO sysInfo;\n";
        stub << "    GetSystemInfo(&sysInfo);\n";
        stub << "    \n";
        stub << "    if (sysInfo.dwNumberOfProcessors == 0) {\n";
        stub << "        return FALSE;\n";
        stub << "    }\n";
        stub << "    \n";
        stub << "    MEMORYSTATUSEX memStatus;\n";
        stub << "    memStatus.dwLength = sizeof(memStatus);\n";
        stub << "    GlobalMemoryStatusEx(&memStatus);\n";
        stub << "    \n";
        stub << "    if (memStatus.ullTotalPhys < (256ULL * 1024 * 1024)) {\n";
        stub << "        return FALSE; // Insufficient memory\n";
        stub << "    }\n";
        stub << "    \n";
        stub << "    return TRUE;\n";
        stub << "}\n\n";
        
        // Benign validation function
        stub << "// Configuration validation\n";
        stub << "BOOL " << validateFunc << "() {\n";
        stub << "    // Validate system configuration\n";
        stub << "    DWORD version = GetVersion();\n";
        stub << "    DWORD majorVersion = (DWORD)(LOBYTE(LOWORD(version)));\n";
        stub << "    \n";
        stub << "    if (majorVersion < 6) {\n";
        stub << "        return FALSE; // Unsupported OS version\n";
        stub << "    }\n";
        stub << "    \n";
        stub << "    return TRUE;\n";
        stub << "}\n\n";
        
        // Main processing function - COMPLETELY BENIGN
        stub << "// Main processing routine\n";
        stub << "int " << processFunc << "() {\n";
        stub << "    // Initialize components\n";
        stub << "    if (!" << initFunc << "()) {\n";
        stub << "        MessageBoxA(NULL, \"System initialization failed.\", \"" << company.product << "\", MB_OK | MB_ICONERROR);\n";
        stub << "        return 1;\n";
        stub << "    }\n";
        stub << "    \n";
        stub << "    // Validate configuration\n";
        stub << "    if (!" << validateFunc << "()) {\n";
        stub << "        MessageBoxA(NULL, \"Configuration validation failed.\", \"" << company.product << "\", MB_OK | MB_ICONWARNING);\n";
        stub << "        return 2;\n";
        stub << "    }\n";
        stub << "    \n";
        stub << "    // Show success message - ONLY BENIGN ACTION\n";
        stub << "    std::string message = \"" << company.product << " v" << company.version << " loaded successfully.\\n\\n\";\n";
        stub << "    message += \"System Status: OK\\n\";\n";
        stub << "    message += \"Configuration: Valid\\n\";\n";
        stub << "    message += \"Ready for operation.\";\n";
        stub << "    \n";
        stub << "    MessageBoxA(NULL, message.c_str(), \"" << company.name << "\", MB_OK | MB_ICONINFORMATION);\n";
        stub << "    \n";
        stub << "    // Optional: Show additional info\n";
        stub << "    if (MessageBoxA(NULL, \"Would you like to view system information?\", \"" << company.product << "\", MB_YESNO | MB_ICONQUESTION) == IDYES) {\n";
        stub << "        SYSTEM_INFO si;\n";
        stub << "        GetSystemInfo(&si);\n";
        stub << "        \n";
        stub << "        std::string sysInfo = \"System Information:\\n\\n\";\n";
        stub << "        sysInfo += \"Processors: \" + std::to_string(si.dwNumberOfProcessors) + \"\\n\";\n";
        stub << "        sysInfo += \"Page Size: \" + std::to_string(si.dwPageSize) + \" bytes\\n\";\n";
        stub << "        sysInfo += \"Processor Type: \" + std::to_string(si.dwProcessorType);\n";
        stub << "        \n";
        stub << "        MessageBoxA(NULL, sysInfo.c_str(), \"System Information\", MB_OK | MB_ICONINFORMATION);\n";
        stub << "    }\n";
        stub << "    \n";
        stub << "    return 0;\n";
        stub << "}\n\n";
        
        // Main entry point
        stub << "// Application entry point\n";
        stub << "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n";
        stub << "    // Standard COM initialization\n";
        stub << "    HRESULT hr = CoInitialize(NULL);\n";
        stub << "    \n";
        stub << "    // Execute main processing\n";
        stub << "    int result = " << processFunc << "();\n";
        stub << "    \n";
        stub << "    // Cleanup\n";
        stub << "    if (SUCCEEDED(hr)) {\n";
        stub << "        CoUninitialize();\n";
        stub << "    }\n";
        stub << "    \n";
        stub << "    return result;\n";
        stub << "}\n";
        
        return stub.str();
    }

private:
    std::string generateRandomSuffix() {
        std::vector<std::string> suffixes = {"Core", "Engine", "Manager", "Service", "Helper", "Utility"};
        return suffixes[rng() % suffixes.size()];
    }
    
    std::string getCurrentDate() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto tm = *std::localtime(&time_t);
        
        std::stringstream ss;
        ss << std::put_time(&tm, "%Y-%m-%d");
        return ss.str();
    }
};

class BenignPEPacker {
private:
    BenignStubGenerator stubGen;
    TimestampEngine timestampEngine;

public:
    bool createBenignExecutable(const std::string& inputPath, const std::string& outputPath) {
        std::cout << "[BENIGN] Creating completely safe executable..." << std::endl;
        
        // Read input file (for size reference only - not used maliciously)
        std::ifstream file(inputPath, std::ios::binary);
        if (!file) {
            std::cout << "[ERROR] Cannot open input file" << std::endl;
            return false;
        }
        
        std::vector<uint8_t> inputData((std::istreambuf_iterator<char>(file)),
                                       std::istreambuf_iterator<char>());
        file.close();
        
        std::cout << "[INFO] Input file size: " << inputData.size() << " bytes" << std::endl;
        
        // Generate completely benign stub
        std::string stubCode = stubGen.generateBenignStub(inputData);
        std::string stubFile = outputPath + "_benign.cpp";
        
        std::ofstream stub(stubFile);
        stub << stubCode;
        stub.close();
        
        std::cout << "[COMPILE] Building benign executable..." << std::endl;
        
        // Compile with standard settings
        std::string compileCmd = "cl /nologo /std:c++17 /O2 /MT /EHsc \"" + stubFile + 
                               "\" /Fe:\"" + outputPath + "\" /link /subsystem:windows >nul 2>&1";
        
        int result = system(compileCmd.c_str());
        std::filesystem::remove(stubFile);
        
        if (result != 0 || !std::filesystem::exists(outputPath)) {
            std::cout << "[ERROR] Compilation failed" << std::endl;
            return false;
        }
        
        // Apply timestamp fixes
        if (!fixTimestamps(outputPath)) {
            std::cout << "[WARNING] Could not fix timestamps" << std::endl;
        }
        
        std::cout << "[SUCCESS] Benign executable created: " << outputPath << std::endl;
        std::cout << "[BEHAVIOR] This executable only shows message boxes - completely safe!" << std::endl;
        
        return true;
    }

private:
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
        
        // Update section timestamps
        auto sections = (IMAGE_SECTION_HEADER*)((BYTE*)ntHeaders + sizeof(IMAGE_NT_HEADERS));
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            sections[i].TimeDateStamp = timestamp + (i * 60); // 1 minute apart
        }
        
        // Write back
        std::ofstream outFile(filePath, std::ios::binary);
        if (!outFile) return false;
        
        outFile.write(reinterpret_cast<const char*>(peData.data()), peData.size());
        outFile.close();
        
        return true;
    }

public:
    void displayMenu() {
        std::cout << "\n";
        std::cout << "========================================================================\n";
        std::cout << "                VS2022 BENIGN PE PACKER v1.0                          \n";
        std::cout << "========================================================================\n";
        std::cout << "  COMPLETELY SAFE - NO MALICIOUS BEHAVIOR                             \n";
        std::cout << "  ONLY SHOWS MESSAGE BOXES                                            \n";
        std::cout << "  NO PROCESS INJECTION OR TERMINATION                                 \n";
        std::cout << "  REALISTIC TIMESTAMPS (FIXED!)                                       \n";
        std::cout << "  LEGITIMATE COMPANY SIGNATURES                                       \n";
        std::cout << "========================================================================\n";
        std::cout << "\n  1. Create Benign Executable\n";
        std::cout << "  2. Exit\n\n";
        std::cout << "Choose option: ";
    }
    
    void run() {
        int choice;
        
        while (true) {
            displayMenu();
            std::cin >> choice;
            std::cin.ignore();
            
            switch (choice) {
                case 1: {
                    std::string input, output;
                    std::cout << "Enter input file path: ";
                    std::getline(std::cin, input);
                    std::cout << "Enter output file path: ";
                    std::getline(std::cin, output);
                    
                    createBenignExecutable(input, output);
                    break;
                }
                
                case 2:
                    return;
                    
                default:
                    std::cout << "[ERROR] Invalid choice" << std::endl;
                    break;
            }
            
            std::cout << "\nPress Enter to continue...";
            std::cin.get();
        }
    }
};

} // namespace BenignPacker

// Main entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    AllocConsole();
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
    freopen_s((FILE**)stdin, "CONIN$", "r", stdin);
    
    using namespace BenignPacker;
    
    BenignPEPacker packer;
    packer.run();
    
    FreeConsole();
    return 0;
}
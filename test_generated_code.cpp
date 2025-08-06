#include <iostream>
#include <fstream>
#include <string>
#include <vector>

// Simulate the benign code generation
std::string generateTestBenignCode() {
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
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    
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
        char productName[256] = {0};
        DWORD productNameSize = sizeof(productName);
        RegQueryValueExA(hKey, "ProductName", NULL, NULL, (LPBYTE)productName, &productNameSize);
        RegCloseKey(hKey);
    }
    
    // Check if debugger is present (anti-analysis)
    if (IsDebuggerPresent()) {
        ExitProcess(0);
    }
    
    // Get system information
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    // Check memory status
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    
    // Simulate legitimate file operations
    char tempPath[MAX_PATH] = {0};
    GetTempPathA(MAX_PATH, tempPath);
    
    // Check for virtualization (anti-VM)
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (hKernel32) {
        FreeLibrary(hKernel32);
    }
    
    // Display benign message
    MessageBoxA(NULL, 
               "Test Company Application\n\nSystem check completed successfully.\n\nVersion: 1.0.0", 
               "Test Company", 
               MB_OK | MB_ICONINFORMATION);
}
)";
}

// Simulate the combined code generation
std::string generateTestCombinedCode() {
    std::string exploitIncludes = ""; // No exploits for test
    std::string benignCode = generateTestBenignCode();
    
    std::string combinedCode = exploitIncludes + "\n";
    combinedCode += benignCode + "\n\n";
    
    // Add simple main function that calls the benign operations
    combinedCode += "int main() {\n";
    combinedCode += "    performBenignOperations();\n";
    combinedCode += "    return 0;\n";
    combinedCode += "}\n";
    
    return combinedCode;
}

int main() {
    std::cout << "=== TESTING CODE GENERATION ===\n\n";
    
    // Generate the test code
    std::string testCode = generateTestCombinedCode();
    
    // Write to file
    std::ofstream testFile("test_generated_source.cpp");
    if (testFile.is_open()) {
        testFile << testCode;
        testFile.close();
        std::cout << "✅ Generated test source: test_generated_source.cpp\n";
        std::cout << "📏 Source code length: " << testCode.length() << " characters\n\n";
    } else {
        std::cout << "❌ Failed to create test file\n";
        return 1;
    }
    
    // Analyze the code for potential issues
    std::cout << "=== CODE ANALYSIS ===\n";
    
    // Check for multiple main functions
    size_t mainCount = 0;
    size_t pos = 0;
    while ((pos = testCode.find("int main(", pos)) != std::string::npos) {
        mainCount++;
        pos += 9;
    }
    std::cout << "🔍 Number of main() functions: " << mainCount << "\n";
    
    // Check for undefined function calls
    std::vector<std::string> functionCalls = {
        "performBenignOperations()",
        "executeHTMLSVGExploit()",
        "executeWinRExploit()",
        "executeInkUrlExploit()",
        "executeDocXlsExploit()",
        "executeXllExploit()"
    };
    
    for (const auto& funcCall : functionCalls) {
        if (testCode.find(funcCall) != std::string::npos) {
            // Check if function is defined
            std::string funcDef = funcCall.substr(0, funcCall.find("("));
            if (testCode.find("void " + funcDef + "(") != std::string::npos ||
                testCode.find("int " + funcDef + "(") != std::string::npos) {
                std::cout << "✅ " << funcCall << " - DEFINED\n";
            } else {
                std::cout << "❌ " << funcCall << " - CALLED but NOT DEFINED\n";
            }
        }
    }
    
    // Check for required includes
    std::vector<std::string> requiredIncludes = {
        "#include <windows.h>",
        "#include <iostream>",
        "#include <fstream>",
        "#include <vector>",
        "#include <string>",
        "#include <thread>",
        "#include <chrono>"
    };
    
    std::cout << "\n=== INCLUDE ANALYSIS ===\n";
    for (const auto& include : requiredIncludes) {
        if (testCode.find(include) != std::string::npos) {
            std::cout << "✅ " << include << "\n";
        } else {
            std::cout << "❌ " << include << " - MISSING\n";
        }
    }
    
    std::cout << "\n=== SUMMARY ===\n";
    if (mainCount == 1) {
        std::cout << "✅ Single main() function - GOOD\n";
    } else {
        std::cout << "❌ Multiple or no main() functions - LINKER WILL FAIL\n";
    }
    
    std::cout << "\n📁 Check test_generated_source.cpp for the actual generated code\n";
    std::cout << "🔧 Try compiling it manually to see exact errors\n";
    
    return 0;
}
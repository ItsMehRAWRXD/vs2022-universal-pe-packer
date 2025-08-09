#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>

// Tool to debug FUD compilation issues
int main() {
    std::cout << "=== FUD Compilation Debug Tool ===\n\n";
    
    // Check if temp source file exists
    std::cout << "1. Looking for temp source files...\n";
    
    // Check for common temp file patterns
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA("temp_*.cpp", &findData);
    
    std::string tempFile;
    if (hFind != INVALID_HANDLE_VALUE) {
        tempFile = findData.cFileName;
        std::cout << "Found temp file: " << tempFile << "\n";
        FindClose(hFind);
    } else {
        std::cout << "No temp_*.cpp files found\n";
        std::cout << "Creating test source to verify compiler...\n";
        
        // Create a test source similar to what the packer generates
        std::ofstream test("test_fud_source.cpp");
        test << "#include <windows.h>\n";
        test << "#include <iostream>\n";
        test << "#include <fstream>\n";
        test << "#include <vector>\n";
        test << "#include <string>\n";
        test << "#include <thread>\n";
        test << "#include <chrono>\n";
        test << "#include <cmath>\n";
        test << "\n";
        test << "void performBenignOperations() {\n";
        test << "    std::this_thread::sleep_for(std::chrono::milliseconds(1000));\n";
        test << "    DWORD version = GetVersion();\n";
        test << "    char computerName[MAX_COMPUTERNAME_LENGTH + 1] = {0};\n";
        test << "    DWORD nameSize = sizeof(computerName);\n";
        test << "    GetComputerNameA(computerName, &nameSize);\n";
        test << "    \n";
        test << "    volatile int calc1 = 123;\n";
        test << "    volatile int calc2 = 456;\n";
        test << "    volatile double mathResult = sin(calc1) * cos(calc2);\n";
        test << "    (void)mathResult;\n";
        test << "    \n";
        test << "    MessageBoxA(NULL, \"FUD Test Successful!\", \"Test\", MB_OK);\n";
        test << "}\n";
        test << "\n";
        test << "int main() {\n";
        test << "    performBenignOperations();\n";
        test << "    return 0;\n";
        test << "}\n";
        test.close();
        
        tempFile = "test_fud_source.cpp";
        std::cout << "Created test source: " << tempFile << "\n";
    }
    
    std::cout << "\n2. Analyzing source file...\n";
    
    // Read and analyze the source file
    std::ifstream sourceFile(tempFile);
    if (sourceFile.is_open()) {
        std::string line;
        int lineNum = 1;
        bool hasMain = false;
        bool hasIncludes = false;
        int mainCount = 0;
        
        std::cout << "Source file content preview:\n";
        std::cout << "----------------------------\n";
        
        while (std::getline(sourceFile, line) && lineNum <= 30) {
            std::cout << lineNum << ": " << line << "\n";
            
            if (line.find("#include") != std::string::npos) {
                hasIncludes = true;
            }
            if (line.find("int main(") != std::string::npos) {
                hasMain = true;
                mainCount++;
            }
            
            lineNum++;
        }
        sourceFile.close();
        
        std::cout << "----------------------------\n";
        std::cout << "Analysis results:\n";
        std::cout << "- Has includes: " << (hasIncludes ? "YES" : "NO") << "\n";
        std::cout << "- Has main(): " << (hasMain ? "YES" : "NO") << "\n";
        std::cout << "- Main count: " << mainCount << "\n";
        
        if (mainCount != 1) {
            std::cout << "⚠️  WARNING: Should have exactly 1 main() function!\n";
        }
    } else {
        std::cout << "❌ Could not read source file\n";
        return 1;
    }
    
    std::cout << "\n3. Testing manual compilation...\n";
    
    // Test different compilation methods
    std::vector<std::pair<std::string, std::string>> methods = {
        {"VS2022 Enterprise vcvars", "cmd /c \"\"C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat\" && cl.exe /nologo /O2 /MT /EHsc \"" + tempFile + "\" /Fe:\"test_manual.exe\" user32.lib kernel32.lib advapi32.lib shell32.lib ole32.lib\""},
        {"Direct cl.exe", "cl.exe /nologo /O2 /MT /EHsc \"" + tempFile + "\" /Fe:\"test_direct.exe\" user32.lib kernel32.lib advapi32.lib shell32.lib ole32.lib"},
        {"Simple compilation", "cl.exe /nologo /EHsc \"" + tempFile + "\" /Fe:\"test_simple.exe\" user32.lib"}
    };
    
    for (const auto& method : methods) {
        std::cout << "\nTrying: " << method.first << "\n";
        std::cout << "Command: " << method.second << "\n";
        
        int result = system(method.second.c_str());
        std::cout << "Result: " << result;
        
        if (result == 0) {
            std::cout << " ✅ SUCCESS!\n";
            
            // Check if exe was created
            std::string exeName = method.second.substr(method.second.find("/Fe:") + 5);
            exeName = exeName.substr(0, exeName.find("\""));
            
            DWORD attrs = GetFileAttributesA(exeName.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES) {
                std::cout << "✅ Executable created: " << exeName << "\n";
                
                // Test execution
                std::cout << "Testing execution...\n";
                system(exeName.c_str());
                
                // This method works - use it as reference
                std::cout << "\n🎉 WORKING METHOD FOUND!\n";
                std::cout << "Use this command format in the packer:\n";
                std::cout << method.second << "\n";
                break;
            } else {
                std::cout << " ❌ No executable created\n";
            }
        } else {
            std::cout << " ❌ FAILED\n";
        }
    }
    
    std::cout << "\n4. Checking compiler errors...\n";
    
    // Try to capture compiler errors
    std::string errorCmd = "cmd /c \"\"C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat\" && cl.exe /nologo /O2 /MT /EHsc \"" + tempFile + "\" /Fe:\"test_error.exe\" user32.lib 2>error_output.txt\"";
    system(errorCmd.c_str());
    
    std::ifstream errorFile("error_output.txt");
    if (errorFile.is_open()) {
        std::cout << "Compiler error output:\n";
        std::cout << "----------------------\n";
        std::string line;
        while (std::getline(errorFile, line)) {
            std::cout << line << "\n";
        }
        errorFile.close();
        std::cout << "----------------------\n";
    }
    
    std::cout << "\n=== Debug Complete ===\n";
    std::cout << "If a working method was found above, update the packer to use that format.\n";
    std::cout << "If all methods failed, there may be a Visual Studio installation issue.\n";
    
    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    
    return 0;
}
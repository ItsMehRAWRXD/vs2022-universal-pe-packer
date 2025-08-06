#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

// Test if we can find and use the compiler
bool testCompilerSetup() {
    std::cout << "=== Testing Compiler Setup ===\n";
    
    // Test 1: Check if cl.exe is in PATH
    std::cout << "Test 1: Checking if cl.exe is in PATH...\n";
    int result = system("cl.exe /? >nul 2>&1");
    if (result == 0) {
        std::cout << "✅ cl.exe found in PATH\n";
        return true;
    } else {
        std::cout << "❌ cl.exe not found in PATH\n";
    }
    
    // Test 2: Try to find Visual Studio installations
    std::cout << "\nTest 2: Looking for Visual Studio installations...\n";
    std::vector<std::string> vsPaths = {
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat",
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat", 
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat",
        "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat",
        "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat",
        "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
    };
    
    std::string workingVcvars;
    for (const auto& path : vsPaths) {
        DWORD attrs = GetFileAttributesA(path.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            std::cout << "✅ Found: " << path << "\n";
            workingVcvars = path;
            break;
        } else {
            std::cout << "❌ Not found: " << path << "\n";
        }
    }
    
    if (workingVcvars.empty()) {
        std::cout << "❌ No Visual Studio installation found!\n";
        return false;
    }
    
    // Test 3: Try compilation with found vcvars
    std::cout << "\nTest 3: Testing compilation with vcvars...\n";
    
    // Create a simple test file
    std::ofstream testFile("compiler_test.cpp");
    testFile << "#include <windows.h>\n";
    testFile << "#include <iostream>\n";
    testFile << "int main() {\n";
    testFile << "    std::cout << \"Compiler test successful!\" << std::endl;\n";
    testFile << "    MessageBoxA(NULL, \"Test\", \"Success\", MB_OK);\n";
    testFile << "    return 0;\n";
    testFile << "}\n";
    testFile.close();
    
    // Try compilation
    std::string compileCmd = "cmd /c \"\"" + workingVcvars + "\" && cl.exe /nologo /EHsc compiler_test.cpp /Fe:compiler_test.exe user32.lib\"";
    std::cout << "Compile command: " << compileCmd << "\n";
    
    result = system(compileCmd.c_str());
    
    if (result == 0) {
        std::cout << "✅ Compilation successful!\n";
        
        // Check if exe was created
        DWORD attrs = GetFileAttributesA("compiler_test.exe");
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            std::cout << "✅ Executable created successfully!\n";
            
            // Test execution
            std::cout << "Testing execution...\n";
            system("compiler_test.exe");
            
            // Cleanup
            DeleteFileA("compiler_test.cpp");
            DeleteFileA("compiler_test.exe");
            DeleteFileA("compiler_test.obj");
            
            return true;
        } else {
            std::cout << "❌ Executable not created\n";
        }
    } else {
        std::cout << "❌ Compilation failed with code " << result << "\n";
    }
    
    return false;
}

// Simple fallback compiler function for testing
bool testSimpleCompilation() {
    std::cout << "\n=== Testing Simple Compilation (No vcvars) ===\n";
    
    // Create test file
    std::ofstream testFile("simple_test.cpp");
    testFile << "#include <iostream>\n";
    testFile << "int main() {\n";
    testFile << "    std::cout << \"Simple test works!\" << std::endl;\n";
    testFile << "    return 0;\n";
    testFile << "}\n";
    testFile.close();
    
    // Try direct cl.exe
    std::string cmd = "cl.exe /nologo /EHsc simple_test.cpp /Fe:simple_test.exe";
    std::cout << "Command: " << cmd << "\n";
    
    int result = system(cmd.c_str());
    
    if (result == 0) {
        std::cout << "✅ Simple compilation works!\n";
        
        DWORD attrs = GetFileAttributesA("simple_test.exe");
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            std::cout << "✅ Simple executable created!\n";
            system("simple_test.exe");
            
            DeleteFileA("simple_test.cpp");
            DeleteFileA("simple_test.exe");
            DeleteFileA("simple_test.obj");
            return true;
        }
    } else {
        std::cout << "❌ Simple compilation failed\n";
    }
    
    return false;
}

int main() {
    std::cout << "FUD Compiler Diagnostic Tool\n";
    std::cout << "=============================\n\n";
    
    bool compilerWorks = testCompilerSetup();
    
    if (!compilerWorks) {
        std::cout << "\nTrying fallback method...\n";
        compilerWorks = testSimpleCompilation();
    }
    
    if (compilerWorks) {
        std::cout << "\n🎉 SOLUTION FOUND!\n";
        std::cout << "The compiler is working. The FUD packer issue might be:\n";
        std::cout << "1. Run the packer from Visual Studio Developer Command Prompt\n";
        std::cout << "2. Or the packer needs to be updated to use the working method\n";
    } else {
        std::cout << "\n❌ COMPILER ISSUE DETECTED!\n";
        std::cout << "Possible solutions:\n";
        std::cout << "1. Install Visual Studio 2019/2022 with C++ development tools\n";
        std::cout << "2. Run from 'Developer Command Prompt for VS 2022'\n";
        std::cout << "3. Add Visual Studio to PATH manually\n";
        std::cout << "4. Check that Windows SDK is installed\n";
    }
    
    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    return 0;
}
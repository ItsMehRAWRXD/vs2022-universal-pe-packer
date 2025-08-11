#include <iostream>
#include <string>
#include <cstdlib>
#include <windows.h>

class VSCompilerDiagnostic {
public:
    static void runDiagnostics() {
        std::cout << "=== Visual Studio Compiler Diagnostics ===" << std::endl;
        
        // Test 1: Check if cl.exe is in PATH
        std::cout << "\n1. Testing cl.exe availability..." << std::endl;
        int result1 = system("cl 2>nul");
        std::cout << "cl.exe direct test result: " << result1 << std::endl;
        
        // Test 2: Test with vcvars64.bat setup
        std::cout << "\n2. Testing with vcvars64.bat setup..." << std::endl;
        std::string vcvarsCmd = "cmd /c \"call \"C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat\" && cl\"";
        int result2 = system(vcvarsCmd.c_str());
        std::cout << "vcvars64.bat + cl test result: " << result2 << std::endl;
        
        // Test 3: Check environment variables
        std::cout << "\n3. Checking environment variables..." << std::endl;
        char* include = getenv("INCLUDE");
        char* lib = getenv("LIB");
        char* path = getenv("PATH");
        
        std::cout << "INCLUDE: " << (include ? "SET" : "NOT SET") << std::endl;
        std::cout << "LIB: " << (lib ? "SET" : "NOT SET") << std::endl;
        std::cout << "PATH contains VS: ";
        if (path && strstr(path, "Microsoft Visual Studio")) {
            std::cout << "YES" << std::endl;
        } else {
            std::cout << "NO" << std::endl;
        }
        
        // Test 4: Create and compile a simple test file
        std::cout << "\n4. Testing simple compilation..." << std::endl;
        createTestFile();
        testSimpleCompilation();
        
        // Test 5: Test with full command like in the packer
        std::cout << "\n5. Testing packer-style compilation..." << std::endl;
        testPackerStyleCompilation();
    }
    
private:
    static void createTestFile() {
        FILE* testFile = fopen("test_simple.cpp", "w");
        if (testFile) {
            fprintf(testFile, "#include <windows.h>\n");
            fprintf(testFile, "#include <iostream>\n");
            fprintf(testFile, "int main() {\n");
            fprintf(testFile, "    std::cout << \"Test compilation successful!\" << std::endl;\n");
            fprintf(testFile, "    MessageBoxA(NULL, \"Test\", \"Success\", MB_OK);\n");
            fprintf(testFile, "    return 0;\n");
            fprintf(testFile, "}\n");
            fclose(testFile);
            std::cout << "Created test_simple.cpp" << std::endl;
        }
    }
    
    static void testSimpleCompilation() {
        std::string cmd = "cmd /c \"call \"C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat\" >nul 2>&1 && cl.exe /nologo test_simple.cpp /Fe:test_simple.exe user32.lib\"";
        std::cout << "Running: " << cmd << std::endl;
        int result = system(cmd.c_str());
        std::cout << "Simple compilation result: " << result << std::endl;
        
        // Check if executable was created
        if (GetFileAttributesA("test_simple.exe") != INVALID_FILE_ATTRIBUTES) {
            std::cout << "✅ test_simple.exe created successfully!" << std::endl;
        } else {
            std::cout << "❌ test_simple.exe NOT created" << std::endl;
        }
    }
    
    static void testPackerStyleCompilation() {
        // Create a file similar to what the packer generates
        FILE* packerTest = fopen("test_packer_style.cpp", "w");
        if (packerTest) {
            fprintf(packerTest, "#include <windows.h>\n");
            fprintf(packerTest, "#include <stdio.h>\n");
            fprintf(packerTest, "#include <stdlib.h>\n");
            fprintf(packerTest, "#include <string.h>\n");
            fprintf(packerTest, "\n");
            fprintf(packerTest, "// Polymorphic variables\n");
            fprintf(packerTest, "static volatile int poly_var_A = 6527;\n");
            fprintf(packerTest, "static volatile int poly_var_B = 9160;\n");
            fprintf(packerTest, "\n");
            fprintf(packerTest, "// PE data placeholder\n");
            fprintf(packerTest, "static unsigned char embedded_pe_data[] = {\n");
            fprintf(packerTest, "    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00\n");
            fprintf(packerTest, "};\n");
            fprintf(packerTest, "\n");
            fprintf(packerTest, "void extract_payload() {\n");
            fprintf(packerTest, "    // Payload extraction logic\n");
            fprintf(packerTest, "    MessageBoxA(NULL, \"Payload extracted\", \"Test\", MB_OK);\n");
            fprintf(packerTest, "}\n");
            fprintf(packerTest, "\n");
            fprintf(packerTest, "int main() {\n");
            fprintf(packerTest, "    // Anti-debug check\n");
            fprintf(packerTest, "    if (IsDebuggerPresent()) {\n");
            fprintf(packerTest, "        ExitProcess(0);\n");
            fprintf(packerTest, "    }\n");
            fprintf(packerTest, "    \n");
            fprintf(packerTest, "    extract_payload();\n");
            fprintf(packerTest, "    return 0;\n");
            fprintf(packerTest, "}\n");
            fclose(packerTest);
            std::cout << "Created test_packer_style.cpp" << std::endl;
        }
        
        // Test compilation with exact packer command style
        std::string packerCmd = "cmd /c \"call \"C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat\" >nul 2>&1 && cl.exe /nologo /O2 /EHsc /DNDEBUG /MD /Fe\"test_packer_output.exe\" \"test_packer_style.cpp\" /link /MACHINE:X64 /SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF user32.lib kernel32.lib advapi32.lib shell32.lib ole32.lib\"";
        
        std::cout << "Packer-style command: " << packerCmd << std::endl;
        int result = system(packerCmd.c_str());
        std::cout << "Packer-style compilation result: " << result << std::endl;
        
        // Check if executable was created
        if (GetFileAttributesA("test_packer_output.exe") != INVALID_FILE_ATTRIBUTES) {
            std::cout << "✅ test_packer_output.exe created successfully!" << std::endl;
            
            // Get file size
            HANDLE hFile = CreateFileA("test_packer_output.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD fileSize = GetFileSize(hFile, NULL);
                std::cout << "File size: " << fileSize << " bytes" << std::endl;
                CloseHandle(hFile);
            }
        } else {
            std::cout << "❌ test_packer_output.exe NOT created" << std::endl;
            
            // Try to capture error output
            std::cout << "Attempting to capture errors..." << std::endl;
            std::string errorCmd = packerCmd + " 2>packer_errors.txt";
            system(errorCmd.c_str());
            
            // Try to read error file
            FILE* errorFile = fopen("packer_errors.txt", "r");
            if (errorFile) {
                char buffer[1024];
                while (fgets(buffer, sizeof(buffer), errorFile)) {
                    std::cout << "ERROR: " << buffer;
                }
                fclose(errorFile);
            }
        }
    }
};

int main() {
    VSCompilerDiagnostic::runDiagnostics();
    
    std::cout << "\n=== RECOMMENDATIONS ===" << std::endl;
    std::cout << "1. If cl.exe tests fail, ensure Visual Studio 2022 Enterprise is installed" << std::endl;
    std::cout << "2. If vcvars64.bat fails, check the path to Visual Studio installation" << std::endl;
    std::cout << "3. If simple compilation works but packer-style fails, there's an issue with the generated source" << std::endl;
    std::cout << "4. Check that all required libraries are available" << std::endl;
    
    system("pause");
    return 0;
}
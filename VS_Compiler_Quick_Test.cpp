#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

// Simple compiler detection
struct SimpleCompilerInfo {
    std::string name;
    std::string vcvarsPath;
    std::string clPath;
    bool found;
};

SimpleCompilerInfo detectCompiler() {
    SimpleCompilerInfo info;
    info.found = false;
    
    // Check common VS 2022 locations
    std::vector<std::pair<std::string, std::string>> paths = {
        {"VS2022 Enterprise", "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise"},
        {"VS2022 Professional", "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional"},
        {"VS2022 Community", "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community"},
        {"VS2019 Enterprise", "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Enterprise"},
        {"VS2019 Professional", "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Professional"},
        {"VS2019 Community", "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community"}
    };
    
    for (const auto& p : paths) {
        std::string vcvars = p.second + "\\VC\\Auxiliary\\Build\\vcvars64.bat";
        std::string cl = p.second + "\\VC\\Tools\\MSVC";
        
        DWORD attrs = GetFileAttributesA(vcvars.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            info.name = p.first;
            info.vcvarsPath = vcvars;
            info.found = true;
            std::cout << "[FOUND] " << p.first << std::endl;
            std::cout << "  vcvars64.bat: " << vcvars << std::endl;
            break;
        } else {
            std::cout << "[NOT FOUND] " << p.first << " - " << vcvars << std::endl;
        }
    }
    
    return info;
}

int main() {
    std::cout << "=== VS Compiler Detection Test ===\n\n";
    
    auto compiler = detectCompiler();
    
    if (!compiler.found) {
        std::cout << "\nERROR: No Visual Studio compiler found!\n";
        std::cout << "Please ensure Visual Studio 2019 or 2022 is installed.\n";
        return 1;
    }
    
    std::cout << "\n=== Testing Simple Compilation ===\n";
    
    // Create a simple test file
    std::cout << "Creating test source file...\n";
    FILE* testFile = nullptr;
    fopen_s(&testFile, "test_simple.cpp", "w");
    if (testFile) {
        fprintf(testFile, "#include <windows.h>\n");
        fprintf(testFile, "#include <iostream>\n");
        fprintf(testFile, "int main() {\n");
        fprintf(testFile, "    std::cout << \"Hello from test!\" << std::endl;\n");
        fprintf(testFile, "    MessageBoxA(NULL, \"Test compilation successful!\", \"Success\", MB_OK);\n");
        fprintf(testFile, "    return 0;\n");
        fprintf(testFile, "}\n");
        fclose(testFile);
        std::cout << "Test source created: test_simple.cpp\n";
    } else {
        std::cout << "ERROR: Could not create test source file!\n";
        return 1;
    }
    
    // Try to compile
    std::string compileCmd = "cmd /c \"\"" + compiler.vcvarsPath + "\" && cl.exe /nologo /EHsc test_simple.cpp /Fe:test_simple.exe user32.lib\"";
    std::cout << "\nCompilation command:\n" << compileCmd << "\n\n";
    std::cout << "Running compilation...\n";
    
    int result = system(compileCmd.c_str());
    
    if (result == 0) {
        std::cout << "\n✅ SUCCESS: Compilation completed!\n";
        
        // Check if output file exists
        DWORD attrs = GetFileAttributesA("test_simple.exe");
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            std::cout << "✅ SUCCESS: Output file created: test_simple.exe\n";
            std::cout << "\nTesting execution...\n";
            system("test_simple.exe");
        } else {
            std::cout << "❌ ERROR: Output file not created\n";
        }
    } else {
        std::cout << "❌ ERROR: Compilation failed with code " << result << "\n";
        std::cout << "This indicates a problem with the Visual Studio setup.\n";
    }
    
    // Cleanup
    DeleteFileA("test_simple.cpp");
    DeleteFileA("test_simple.exe");
    DeleteFileA("test_simple.obj");
    
    std::cout << "\n=== Diagnostic Complete ===\n";
    std::cout << "Press Enter to exit...";
    std::cin.get();
    
    return 0;
}
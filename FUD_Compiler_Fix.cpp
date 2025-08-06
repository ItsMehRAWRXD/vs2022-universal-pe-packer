#include <windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <vector> // Added for testFUDCompilation

// Fixed FUD Compiler with proper VS environment setup
class FUDCompiler {
public:
    static bool compileSource(const std::string& sourceFile, const std::string& outputFile) {
        // Method 1: Try VsDevCmd.bat (more reliable than vcvars64.bat)
        std::string cmd1 = "cmd /c \"";
        cmd1 += "call \\\"C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\Common7\\Tools\\VsDevCmd.bat\\\" -arch=x64 -host_arch=x64 >nul 2>&1 && ";
        cmd1 += "cl.exe /nologo /O2 /EHsc /DNDEBUG /MD ";
        cmd1 += "/Fe\\\"" + outputFile + "\\\" ";
        cmd1 += "\\\"" + sourceFile + "\\\" ";
        cmd1 += "/link /SUBSYSTEM:CONSOLE user32.lib kernel32.lib advapi32.lib\"";
        
        std::cout << "Trying VS 2022 Enterprise compilation...\n";
        int result1 = system(cmd1.c_str());
        
        if (result1 == 0 && fileExists(outputFile)) {
            std::cout << "✅ SUCCESS: Compiled with VS 2022 Enterprise\n";
            return true;
        }
        
        // Method 2: Try VS 2022 Community
        std::string cmd2 = "cmd /c \"";
        cmd2 += "call \\\"C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\Tools\\VsDevCmd.bat\\\" -arch=x64 -host_arch=x64 >nul 2>&1 && ";
        cmd2 += "cl.exe /nologo /O2 /EHsc /DNDEBUG /MD ";
        cmd2 += "/Fe\\\"" + outputFile + "\\\" ";
        cmd2 += "\\\"" + sourceFile + "\\\" ";
        cmd2 += "/link /SUBSYSTEM:CONSOLE user32.lib kernel32.lib advapi32.lib\"";
        
        std::cout << "Trying VS 2022 Community compilation...\n";
        int result2 = system(cmd2.c_str());
        
        if (result2 == 0 && fileExists(outputFile)) {
            std::cout << "✅ SUCCESS: Compiled with VS 2022 Community\n";
            return true;
        }
        
        // Method 3: Try direct cl.exe (if in PATH)
        std::string cmd3 = "cl.exe /nologo /O2 /EHsc /DNDEBUG /MD ";
        cmd3 += "/Fe\\\"" + outputFile + "\\\" ";
        cmd3 += "\\\"" + sourceFile + "\\\" ";
        cmd3 += "/link /SUBSYSTEM:CONSOLE user32.lib kernel32.lib advapi32.lib";
        
        std::cout << "Trying direct cl.exe compilation...\n";
        int result3 = system(cmd3.c_str());
        
        if (result3 == 0 && fileExists(outputFile)) {
            std::cout << "✅ SUCCESS: Compiled with direct cl.exe\n";
            return true;
        }
        
        // Method 4: Try MinGW fallback
        std::string cmd4 = "gcc -O2 -mwindows ";
        cmd4 += "\\\"" + sourceFile + "\\\" ";
        cmd4 += "-o \\\"" + outputFile + "\\\" ";
        cmd4 += "-luser32 -lkernel32 -ladvapi32";
        
        std::cout << "Trying MinGW compilation...\n";
        int result4 = system(cmd4.c_str());
        
        if (result4 == 0 && fileExists(outputFile)) {
            std::cout << "✅ SUCCESS: Compiled with MinGW\n";
            return true;
        }
        
        std::cout << "❌ FAILED: All compilation methods failed\n";
        std::cout << "VS2022 Enterprise result: " << result1 << "\n";
        std::cout << "VS2022 Community result: " << result2 << "\n";
        std::cout << "Direct cl.exe result: " << result3 << "\n";
        std::cout << "MinGW result: " << result4 << "\n";
        
        return false;
    }
    
    static bool fileExists(const std::string& filename) {
        DWORD attrs = GetFileAttributesA(filename.c_str());
        return (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY));
    }
    
    // Test compilation with provided FUD sources
    static void testFUDCompilation() {
        std::cout << "=== FUD Source Compilation Test ===\n";
        
        // Test with both provided sources
        std::vector<std::string> testSources = {
            "fud_source1.cpp",
            "fud_source2.cpp"
        };
        
        for (int i = 0; i < testSources.size(); i++) {
            std::string sourceFile = testSources[i];
            std::string outputFile = "fud_output" + std::to_string(i + 1) + ".exe";
            
            std::cout << "\n--- Testing " << sourceFile << " ---\n";
            
            if (fileExists(sourceFile)) {
                bool success = compileSource(sourceFile, outputFile);
                if (success) {
                    std::cout << "✅ " << sourceFile << " → " << outputFile << " (SUCCESS)\n";
                } else {
                    std::cout << "❌ " << sourceFile << " → FAILED\n";
                    std::cout << "💡 Try manual compilation:\n";
                    std::cout << "   cl /O2 /EHsc " << sourceFile << " /Fe:" << outputFile << " user32.lib\n";
                }
            } else {
                std::cout << "⚠️  " << sourceFile << " not found\n";
            }
        }
    }
};

int main() {
    FUDCompiler::testFUDCompilation();
    
    std::cout << "\n=== Manual Compilation Commands ===\n";
    std::cout << "If auto-compilation fails, use these commands:\n\n";
    std::cout << "VS 2022 Developer Command Prompt:\n";
    std::cout << "  cl /nologo /O2 /EHsc source.cpp /Fe:output.exe user32.lib\n\n";
    std::cout << "MinGW:\n";
    std::cout << "  gcc -O2 -mwindows source.cpp -o output.exe -luser32 -lkernel32\n\n";
    std::cout << "Online Compiler (compiler.com):\n";
    std::cout << "  Copy source code → Select C++ → Add flags: -luser32\n\n";
    
    return 0;
}
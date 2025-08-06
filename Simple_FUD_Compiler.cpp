#include <windows.h>
#include <iostream>
#include <string>
#include <fstream>

// Simplified FUD Compiler - assumes VS environment is already set
class SimpleFUDCompiler {
public:
    static bool compileSource(const std::string& sourceFile, const std::string& outputFile) {
        // Use simple cl.exe command (works when VS environment is pre-set)
        std::string cmd = "cl.exe /nologo /O2 /EHsc ";
        cmd += "\"" + sourceFile + "\" ";
        cmd += "/Fe:\"" + outputFile + "\" ";
        cmd += "user32.lib kernel32.lib advapi32.lib";
        
        std::cout << "Compiling: " << sourceFile << " -> " << outputFile << std::endl;
        std::cout << "Command: " << cmd << std::endl;
        
        int result = system(cmd.c_str());
        
        if (result == 0 && fileExists(outputFile)) {
            std::cout << "✅ SUCCESS: Compilation completed" << std::endl;
            return true;
        } else {
            std::cout << "❌ FAILED: Compilation failed (result code: " << result << ")" << std::endl;
            std::cout << "💡 Make sure you're running from VS Developer Command Prompt" << std::endl;
            return false;
        }
    }
    
    static bool fileExists(const std::string& filename) {
        DWORD attrs = GetFileAttributesA(filename.c_str());
        return (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY));
    }
    
    // Batch compile multiple FUD sources
    static void batchCompile(const std::vector<std::string>& sourceFiles) {
        std::cout << "=== Batch FUD Compilation ===" << std::endl;
        
        int successCount = 0;
        for (size_t i = 0; i < sourceFiles.size(); i++) {
            std::string sourceFile = sourceFiles[i];
            std::string outputFile = "fud_" + std::to_string(i + 1) + ".exe";
            
            std::cout << "\n[" << (i + 1) << "/" << sourceFiles.size() << "] ";
            
            if (fileExists(sourceFile)) {
                if (compileSource(sourceFile, outputFile)) {
                    successCount++;
                }
            } else {
                std::cout << "⚠️ Source file not found: " << sourceFile << std::endl;
            }
        }
        
        std::cout << "\n=== Results ===" << std::endl;
        std::cout << "✅ Success: " << successCount << "/" << sourceFiles.size() << std::endl;
        
        if (successCount < sourceFiles.size()) {
            std::cout << "\n💡 If compilation failed:" << std::endl;
            std::cout << "1. Make sure you're in VS Developer Command Prompt" << std::endl;
            std::cout << "2. Or run: call \"C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\Common7\\Tools\\VsDevCmd.bat\"" << std::endl;
        }
    }
};

int main() {
    std::cout << "Simple FUD Compiler - Fixed Version" << std::endl;
    std::cout << "====================================" << std::endl;
    
    // Test with generated FUD sources
    std::vector<std::string> sources = {
        "source1.cpp",  // The polymorphic source you just compiled manually
        "source2.cpp"   // Second polymorphic source
    };
    
    // Check if we're in VS environment
    std::cout << "Testing VS environment..." << std::endl;
    int envTest = system("cl >nul 2>&1");
    
    if (envTest == 0) {
        std::cout << "✅ VS environment detected - cl.exe available" << std::endl;
        SimpleFUDCompiler::batchCompile(sources);
    } else {
        std::cout << "❌ VS environment not set" << std::endl;
        std::cout << "Please run from VS Developer Command Prompt or execute:" << std::endl;
        std::cout << "call \"C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\Common7\\Tools\\VsDevCmd.bat\"" << std::endl;
        
        // Show what the compilation commands would be
        std::cout << "\nManual compilation commands:" << std::endl;
        for (size_t i = 0; i < sources.size(); i++) {
            std::cout << "cl /nologo /O2 /EHsc " << sources[i] << " /Fe:fud_" << (i + 1) << ".exe user32.lib" << std::endl;
        }
    }
    
    return 0;
}
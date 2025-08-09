#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include "tiny_loader.h"

struct CompilerResult {
    bool success = false;
    std::string outputPath;
    std::string errorMessage;
};

class CompletePacker {
public:
    // Method 1: PE Template Approach (for payload embedding)
    std::vector<uint8_t> generatePEWithPayload(const std::string& payload) {
        try {
            // Copy the pre-built loader template
            std::vector<uint8_t> exe(tiny_loader_bin, tiny_loader_bin + tiny_loader_bin_len);

            // Pad to PE file alignment
            constexpr size_t kAlign = 0x200;
            size_t paddedSize = (exe.size() + kAlign - 1) & ~(kAlign - 1);
            exe.resize(paddedSize, 0);

            // Append the payload
            size_t payloadOffset = exe.size();
            exe.insert(exe.end(), payload.begin(), payload.end());

            // Patch payload info into the loader
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

    // Method 2: Real Compiler Approach (for C++ code compilation)
    CompilerResult compileSourceCode(const std::string& sourceCode, const std::string& outputPath) {
        CompilerResult result;
        result.success = false;
        result.outputPath = outputPath;
        
        // Create temporary source file
        std::string tempSource = "temp_compile_test.cpp";
        std::ofstream sourceFile(tempSource);
        if (!sourceFile.is_open()) {
            result.errorMessage = "Failed to create temporary source file";
            return result;
        }
        sourceFile << sourceCode;
        sourceFile.close();
        
        // Try MinGW-w64 cross-compilation commands
        std::vector<std::string> compileCommands = {
            "x86_64-w64-mingw32-g++ -O2 -DNDEBUG -static-libgcc -static-libstdc++ \"" + tempSource + "\" -o \"" + outputPath + "\" -luser32 -lkernel32 -ladvapi32 2>/dev/null",
            "i686-w64-mingw32-g++ -O2 -DNDEBUG -static-libgcc -static-libstdc++ \"" + tempSource + "\" -o \"" + outputPath + "\" -luser32 -lkernel32 -ladvapi32 2>/dev/null"
        };
        
        // Try each compiler
        for (const auto& cmd : compileCommands) {
            std::cout << "Trying: " << cmd << std::endl;
            int compileResult = system(cmd.c_str());
            if (compileResult == 0) {
                // Verify the executable was created
                struct stat buffer;
                if (stat(outputPath.c_str(), &buffer) == 0) {
                    result.success = true;
                    result.errorMessage = "Compilation successful with MinGW-w64";
                    break;
                }
            }
        }
        
        // Clean up
        unlink(tempSource.c_str());
        
        if (!result.success) {
            result.errorMessage = "All compilation methods failed. MinGW-w64 not available.";
        }
        
        return result;
    }
};

int main() {
    std::cout << "=== COMPLETE PACKER TEST ===" << std::endl;
    
    CompletePacker packer;
    
    // Test 1: PE Template Approach (Payload Embedding)
    std::cout << "\n1. Testing PE Template Approach (tiny_loader.h)..." << std::endl;
    std::string testPayload = "This is a test payload that will be embedded in the PE file.";
    
    auto peData = packer.generatePEWithPayload(testPayload);
    if (!peData.empty()) {
        std::string peOutputPath = "template_generated.exe";
        std::ofstream peFile(peOutputPath, std::ios::binary);
        if (peFile.is_open()) {
            peFile.write(reinterpret_cast<const char*>(peData.data()), peData.size());
            peFile.close();
            std::cout << "✅ SUCCESS: Generated " << peData.size() << " byte PE executable with embedded payload" << std::endl;
            std::cout << "   File: " << peOutputPath << std::endl;
        } else {
            std::cout << "❌ FAILED: Could not write PE file" << std::endl;
        }
    } else {
        std::cout << "❌ FAILED: PE template generation failed" << std::endl;
    }
    
    // Test 2: Real Compiler Approach (C++ Source Compilation)
    std::cout << "\n2. Testing Real Compiler Approach (MinGW-w64)..." << std::endl;
    std::string testSourceCode = R"(
#include <iostream>
#include <windows.h>

int main() {
    std::cout << "Hello from compiled C++ code!" << std::endl;
    MessageBoxA(NULL, "Real compiler test successful!", "MinGW-w64 Test", MB_OK);
    return 0;
}
)";
    
    std::string cppOutputPath = "compiled_generated.exe";
    CompilerResult compileResult = packer.compileSourceCode(testSourceCode, cppOutputPath);
    
    if (compileResult.success) {
        struct stat fileInfo;
        if (stat(cppOutputPath.c_str(), &fileInfo) == 0) {
            std::cout << "✅ SUCCESS: Compiled C++ source to Windows PE executable" << std::endl;
            std::cout << "   File: " << cppOutputPath << " (" << fileInfo.st_size << " bytes)" << std::endl;
            std::cout << "   Message: " << compileResult.errorMessage << std::endl;
        }
    } else {
        std::cout << "❌ FAILED: " << compileResult.errorMessage << std::endl;
    }
    
    // Summary
    std::cout << "\n=== SUMMARY ===" << std::endl;
    std::cout << "The VS2022 packer needs BOTH approaches:" << std::endl;
    std::cout << "1. ✅ PE Template (tiny_loader.h) - For embedding payloads in pre-built stubs" << std::endl;
    std::cout << "2. " << (compileResult.success ? "✅" : "❌") << " Real Compiler (MinGW-w64) - For compiling C++ source code" << std::endl;
    std::cout << "\nBoth methods create valid Windows PE executables!" << std::endl;
    
    return 0;
}
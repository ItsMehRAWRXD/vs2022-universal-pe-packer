#pragma warning(disable: 4267)  // size_t conversion warnings
#pragma warning(disable: 26444) // uninitialized local variable
#pragma warning(disable: 26495) // uninitialized member variable
#pragma warning(disable: 4244)  // conversion warnings
#pragma warning(disable: 26812) // enum class preference warnings
#pragma warning(disable: 6001)  // using uninitialized memory
#pragma warning(disable: 4566)  // character cannot be represented in code page

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <cstring>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")
#else
#include <unistd.h>
#include <sys/time.h>
// Note: For Linux, install libcurl-dev or compile without URL features
// #include <curl/curl.h>
#endif

class VS2022MenuEncryptor {
private:
    std::mt19937_64 rng;
    
    // Enhanced auto-compilation helper function (supports C++ and MASM)
    void autoCompile(const std::string& sourceFile) {
        std::cout << "[COMPILE] Auto-compiling to executable..." << std::endl;

        // Determine file type by extension
        std::string extension = sourceFile.substr(sourceFile.find_last_of('.'));
        std::string baseName = sourceFile.substr(0, sourceFile.find_last_of('.'));
        std::string exeName = baseName + ".exe";
        std::string compileCmd;
        int result = -1;

        if (extension == ".cpp" || extension == ".c") {
            // C++ compilation
            std::cout << "[INFO] Detected C++ source file" << std::endl;
#ifdef _WIN32
            // Try g++ first (MinGW/TDM-GCC)
            compileCmd = "g++ -std=c++17 -O2 -static \"" + sourceFile + "\" -o \"" + exeName + "\" -lwininet -ladvapi32 2>nul";
            result = system(compileCmd.c_str());

            if (result != 0) {
                // Fallback to cl.exe (Visual Studio)
                compileCmd = "cl /std:c++17 /O2 \"" + sourceFile + "\" /Fe:\"" + exeName + "\" wininet.lib advapi32.lib 2>nul";
                result = system(compileCmd.c_str());
            }
#else
            compileCmd = "g++ -std=c++17 -O2 \"" + sourceFile + "\" -o \"" + exeName + "\"";
            result = system(compileCmd.c_str());
#endif
        }
        else if (extension == ".asm") {
            // MASM assembly compilation
            std::cout << "[INFO] Detected MASM assembly source file" << std::endl;
#ifdef _WIN32
            // Use MASM32 or Visual Studio MASM
            compileCmd = "ml /c /coff \"" + sourceFile + "\" && link /subsystem:windows \"" + baseName + ".obj\" /out:\"" + exeName + "\" 2>nul";
            result = system(compileCmd.c_str());
            
            // Clean up .obj file
            std::string cleanupCmd = "del \"" + baseName + ".obj\" 2>nul";
            system(cleanupCmd.c_str());
#endif
        }

        if (result == 0) {
            std::cout << "✅ [SUCCESS] Executable created: " << exeName << std::endl;
            std::cout << "📋 [INFO] Compile command used: " << compileCmd << std::endl;
        } else {
            std::cout << "❌ [ERROR] Compilation failed. Manual compilation required." << std::endl;
            std::cout << "📋 [INFO] Attempted command: " << compileCmd << std::endl;
        }
    }
    
    struct TripleKey {
        std::vector<uint8_t> chacha_key;
        std::vector<uint8_t> chacha_nonce;
        std::vector<uint8_t> aes_key;
        std::vector<uint8_t> xor_key;
        uint32_t encryption_order;
    };
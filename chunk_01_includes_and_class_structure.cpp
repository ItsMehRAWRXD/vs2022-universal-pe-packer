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

    // HTTP download functionality
#ifdef _WIN32
    bool downloadFile(const std::string& url, std::vector<uint8_t>& fileData) {
        std::cout << "📥 Downloading from: " << url << std::endl;
        
        HINTERNET hInternet = InternetOpenA("UPX-Style Encryptor", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (!hInternet) {
            std::cout << "❌ Failed to initialize WinINet" << std::endl;
            return false;
        }
        
        HINTERNET hUrl = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (!hUrl) {
            std::cout << "❌ Failed to open URL" << std::endl;
            InternetCloseHandle(hInternet);
            return false;
        }
        
        char buffer[8192];
        DWORD bytesRead;
        size_t totalBytes = 0;
        
        while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            fileData.insert(fileData.end(), buffer, buffer + bytesRead);
            totalBytes += bytesRead;
            if (totalBytes % 10240 == 0) { // Progress every 10KB
                std::cout << "📥 Downloaded: " << totalBytes << " bytes...\r" << std::flush;
            }
        }
        
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        
        if (!fileData.empty()) {
            std::cout << "\n✅ Download complete: " << fileData.size() << " bytes" << std::endl;
            return true;
        }
        
        std::cout << "\n❌ Download failed or empty file" << std::endl;
        return false;
    }
#else
    bool downloadFile(const std::string& url, std::vector<uint8_t>& fileData) {
        std::cout << "📥 Attempting download from: " << url << std::endl;
        std::cout << "⚠️  Linux URL download requires wget/curl. Trying wget..." << std::endl;
        
        // Use wget as fallback for Linux
        std::string tempFile = "/tmp/upx_download_" + std::to_string(getpid());
        std::string wgetCmd = "wget -q -O " + tempFile + " \"" + url + "\"";
        
        int result = system(wgetCmd.c_str());
        if (result != 0) {
            std::cout << "❌ wget failed, trying curl..." << std::endl;
            std::string curlCmd = "curl -s -o " + tempFile + " \"" + url + "\"";
            result = system(curlCmd.c_str());
            if (result != 0) {
                std::cout << "❌ Both wget and curl failed. Install wget or curl for URL support." << std::endl;
                return false;
            }
        }
        
        // Read the downloaded file
        std::ifstream file(tempFile, std::ios::binary);
        if (!file) {
            std::cout << "❌ Failed to open downloaded file" << std::endl;
            unlink(tempFile.c_str());
            return false;
        }
        
        fileData.assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        unlink(tempFile.c_str());
        
        if (!fileData.empty()) {
            std::cout << "✅ Download complete: " << fileData.size() << " bytes" << std::endl;
            return true;
        }
        
        std::cout << "❌ Download failed or empty file" << std::endl;
        return false;
    }
#endif

    // Enhanced entropy gathering
    std::vector<uint64_t> gatherEntropy() {
        std::vector<uint64_t> entropy;
        
#ifdef _WIN32
        LARGE_INTEGER perf_counter;
        QueryPerformanceCounter(&perf_counter);
        entropy.push_back(perf_counter.QuadPart);
        
        HCRYPTPROV hProv;
        if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            uint64_t random_val;
            if (CryptGenRandom(hProv, sizeof(random_val), (BYTE*)&random_val)) {
                entropy.push_back(random_val);
            }
            CryptReleaseContext(hProv, 0);
        }
#else
        struct timeval tv;
        gettimeofday(&tv, nullptr);
        entropy.push_back(tv.tv_sec * 1000000 + tv.tv_usec);
        entropy.push_back(getpid());
#endif
        
        auto now = std::chrono::high_resolution_clock::now();
        entropy.push_back(now.time_since_epoch().count());
        entropy.push_back(reinterpret_cast<uint64_t>(&entropy));
        
        return entropy;
    }
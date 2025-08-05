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

    // ChaCha20 implementation
    void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = (d << 16) | (d >> 16);
        c += d; b ^= c; b = (b << 12) | (b >> 20);
        a += b; d ^= a; d = (d << 8) | (d >> 24);
        c += d; b ^= c; b = (b << 7) | (b >> 25);
    }

    void chachaBlock(uint32_t out[16], const uint32_t in[16]) {
        for (int i = 0; i < 16; i++) out[i] = in[i];
        
        for (int i = 0; i < 10; i++) {
            quarterRound(out[0], out[4], out[8], out[12]);
            quarterRound(out[1], out[5], out[9], out[13]);
            quarterRound(out[2], out[6], out[10], out[14]);
            quarterRound(out[3], out[7], out[11], out[15]);
            
            quarterRound(out[0], out[5], out[10], out[15]);
            quarterRound(out[1], out[6], out[11], out[12]);
            quarterRound(out[2], out[7], out[8], out[13]);
            quarterRound(out[3], out[4], out[9], out[14]);
        }
        
        for (int i = 0; i < 16; i++) out[i] += in[i];
    }

    void initChachaState(uint32_t state[16], const uint8_t key[32], const uint8_t nonce[12]) {
        const char* constants = "expand 32-byte k";
        memcpy(state, constants, 16);
        memcpy(state + 4, key, 32);
        state[12] = 0;
        memcpy(state + 13, nonce, 12);
    }

    void chacha20Crypt(std::vector<uint8_t>& data, const uint8_t key[32], const uint8_t nonce[12]) {
        uint32_t state[16];
        initChachaState(state, key, nonce);
        
        for (size_t i = 0; i < data.size(); i += 64) {
            uint32_t keystream[16];
            chachaBlock(keystream, state);
            
            uint8_t* ks_bytes = (uint8_t*)keystream;
            for (size_t j = 0; j < 64 && i + j < data.size(); j++) {
                data[i + j] ^= ks_bytes[j];
            }
            
            state[12]++;
        }
    }
    // AES S-box
    void aesStreamCrypt(std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
        static const uint8_t sbox[256] = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        };
        
        for (size_t i = 0; i < data.size(); i++) {
            uint8_t keyByte = key[i % key.size()];
            uint8_t nonceByte = (i >> 8) ^ (i & 0xFF);
            uint8_t mixedKey = sbox[keyByte] ^ nonceByte;
            data[i] ^= mixedKey;
        }
    }

    // Enhanced XOR
    void xorCrypt(std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
        for (size_t i = 0; i < data.size(); i++) {
            uint8_t keyByte = key[i % key.size()];
            uint8_t posByte = (i * 0x9E3779B9) & 0xFF;
            data[i] ^= keyByte ^ posByte;
        }
    }

    TripleKey generateKeys() {
        TripleKey keys;
        auto entropy = gatherEntropy();
        
        std::seed_seq seed(entropy.begin(), entropy.end());
        rng.seed(seed);
        
        keys.chacha_key.resize(32);
        keys.chacha_nonce.resize(12);
        keys.aes_key.resize(32);
        keys.xor_key.resize(64);
        
        for (auto& k : keys.chacha_key) k = rng() & 0xFF;
        for (auto& n : keys.chacha_nonce) n = rng() & 0xFF;
        for (auto& k : keys.aes_key) k = rng() & 0xFF;
        for (auto& k : keys.xor_key) k = rng() & 0xFF;
        
        keys.encryption_order = rng() % 6;
        
        return keys;
    }

    std::string bytesToBigDecimal(const std::vector<uint8_t>& bytes) {
        std::vector<uint8_t> result = {0};
        
        for (uint8_t byte : bytes) {
            int carry = 0;
            for (int i = result.size() - 1; i >= 0; i--) {
                int prod = result[i] * 256 + carry;
                result[i] = prod % 10;
                carry = prod / 10;
            }

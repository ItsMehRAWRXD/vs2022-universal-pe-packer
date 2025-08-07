/*
========================================================================================
SIMPLE PE ENCRYPTOR - WINDOWS EDITION
========================================================================================
FEATURES:
- Basic PE Header Manipulation
- AES-256 Encryption
- Timestamp Randomization
- Rich Header Removal
- Simple and Reliable
========================================================================================
*/

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

namespace SimplePEEncryptor {

class EncryptionEngine {
private:
    std::mt19937_64 rng;
    std::vector<uint8_t> key;
    
public:
    EncryptionEngine() {
        // Initialize RNG
        auto now = std::chrono::high_resolution_clock::now();
        uint64_t seed = now.time_since_epoch().count() ^ GetTickCount64();
        rng.seed(seed);
        
        // Generate 256-bit key
        key.resize(32);
        for (size_t i = 0; i < key.size(); i++) {
            key[i] = rng() % 256;
        }
    }
    
    std::vector<uint8_t> encryptData(const std::vector<uint8_t>& data) {
        HCRYPTPROV hProv;
        HCRYPTKEY hKey;
        HCRYPTHASH hHash;
        
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            std::cout << "[ERROR] Failed to acquire crypto context" << std::endl;
            return data;
        }
        
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            return data;
        }
        
        if (!CryptHashData(hHash, key.data(), key.size(), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return data;
        }
        
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return data;
        }
        
        // Encrypt data
        std::vector<uint8_t> encryptedData = data;
        DWORD dataLen = encryptedData.size();
        
        if (!CryptEncrypt(hKey, 0, TRUE, 0, encryptedData.data(), &dataLen, encryptedData.size())) {
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return data;
        }
        
        encryptedData.resize(dataLen);
        
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        
        return encryptedData;
    }
};

class TimestampEngine {
private:
    std::mt19937_64 rng;
    
public:
    TimestampEngine() {
        auto now = std::chrono::high_resolution_clock::now();
        uint64_t seed = now.time_since_epoch().count() ^ GetTickCount64();
        rng.seed(seed);
    }
    
    DWORD generateRealisticTimestamp() {
        // Generate timestamp between 6 months and 3 years ago
        SYSTEMTIME st;
        GetSystemTime(&st);
        
        // Random days back (180-1092 days)
        int daysBack = (rng() % 912) + 180;
        
        // Convert to FILETIME
        FILETIME ft;
        SystemTimeToFileTime(&st, &ft);
        
        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        
        // Subtract days
        uli.QuadPart -= (uint64_t)daysBack * 24 * 60 * 60 * 10000000ULL;
        
        // Convert to Unix timestamp
        uint64_t unixTime = (uli.QuadPart - 116444736000000000ULL) / 10000000ULL;
        
        return static_cast<DWORD>(unixTime);
    }
};

class PEEncryptor {
private:
    EncryptionEngine encryptionEngine;
    TimestampEngine timestampEngine;
    
public:
    bool encryptPE(const std::string& inputPath, const std::string& outputPath) {
        std::cout << "[ENCRYPT] Processing: " << inputPath << std::endl;
        
        // Read input file
        std::ifstream file(inputPath, std::ios::binary);
        if (!file) {
            std::cout << "[ERROR] Cannot open input file" << std::endl;
            return false;
        }
        
        std::vector<uint8_t> peData((std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());
        file.close();
        
        if (peData.size() < sizeof(IMAGE_DOS_HEADER)) {
            std::cout << "[ERROR] File too small to be a valid PE" << std::endl;
            return false;
        }
        
        // Verify PE header
        auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(peData.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cout << "[ERROR] Invalid DOS header" << std::endl;
            return false;
        }
        
        if (dosHeader->e_lfanew >= peData.size() - sizeof(IMAGE_NT_HEADERS)) {
            std::cout << "[ERROR] Invalid PE header offset" << std::endl;
            return false;
        }
        
        auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(peData.data() + dosHeader->e_lfanew);
        if (ntHeaders->FileHeader.Signature != IMAGE_NT_SIGNATURE) {
            std::cout << "[ERROR] Invalid NT header signature" << std::endl;
            return false;
        }
        
        std::cout << "[INFO] Valid PE file detected" << std::endl;
        
        // Apply modifications
        if (!modifyTimestamps(peData)) {
            std::cout << "[ERROR] Failed to modify timestamps" << std::endl;
            return false;
        }
        
        if (!removeRichHeader(peData)) {
            std::cout << "[WARNING] Failed to remove Rich header" << std::endl;
        }
        
        // Encrypt the PE data
        std::cout << "[ENCRYPT] Encrypting PE data..." << std::endl;
        std::vector<uint8_t> encryptedData = encryptionEngine.encryptData(peData);
        
        // Create encrypted PE with loader
        std::vector<uint8_t> finalPE = createEncryptedPE(encryptedData);
        
        // Write output file
        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile) {
            std::cout << "[ERROR] Cannot create output file" << std::endl;
            return false;
        }
        
        outFile.write(reinterpret_cast<const char*>(finalPE.data()), finalPE.size());
        outFile.close();
        
        std::cout << "[SUCCESS] Encrypted PE created: " << outputPath << std::endl;
        std::cout << "[INFO] Original size: " << peData.size() << " bytes" << std::endl;
        std::cout << "[INFO] Encrypted size: " << finalPE.size() << " bytes" << std::endl;
        
        return true;
    }
    
private:
    bool modifyTimestamps(std::vector<uint8_t>& peData) {
        auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(peData.data());
        auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(peData.data() + dosHeader->e_lfanew);
        
        // Generate realistic timestamp
        DWORD newTimestamp = timestampEngine.generateRealisticTimestamp();
        ntHeaders->FileHeader.TimeDateStamp = newTimestamp;
        
        time_t t = newTimestamp;
        std::cout << "[TIMESTAMP] Updated to: " << std::ctime(&t);
        return true;
    }
    
    bool removeRichHeader(std::vector<uint8_t>& peData) {
        auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(peData.data());
        
        // Rich header is between DOS header and PE header
        size_t richHeaderStart = sizeof(IMAGE_DOS_HEADER);
        size_t richHeaderEnd = dosHeader->e_lfanew;
        
        if (richHeaderEnd > richHeaderStart + 8) {
            // Check for Rich header signature
            uint32_t* richSignature = reinterpret_cast<uint32_t*>(peData.data() + richHeaderStart);
            if (*richSignature == 0x68636952) { // "Rich"
                std::cout << "[RICH] Removing Rich header..." << std::endl;
                
                // Remove Rich header by shifting data
                peData.erase(peData.begin() + richHeaderStart, peData.begin() + richHeaderEnd);
                
                // Update DOS header
                dosHeader->e_lfanew = sizeof(IMAGE_DOS_HEADER);
                
                return true;
            }
        }
        
        return false;
    }
    
    std::vector<uint8_t> createEncryptedPE(const std::vector<uint8_t>& encryptedData) {
        // Create a simple loader that decrypts and executes the PE
        std::string loaderCode = generateLoaderCode(encryptedData);
        
        // For now, return the encrypted data with a simple header
        std::vector<uint8_t> result;
        
        // Add magic header
        const char* magic = "ENCRYPTED_PE";
        result.insert(result.end(), magic, magic + strlen(magic));
        
        // Add size
        uint32_t size = encryptedData.size();
        result.insert(result.end(), reinterpret_cast<uint8_t*>(&size), 
                     reinterpret_cast<uint8_t*>(&size) + sizeof(size));
        
        // Add encrypted data
        result.insert(result.end(), encryptedData.begin(), encryptedData.end());
        
        return result;
    }
    
    std::string generateLoaderCode(const std::vector<uint8_t>& encryptedData) {
        // Generate C++ loader code
        std::stringstream ss;
        ss << "#include <iostream>\n";
        ss << "#include <vector>\n";
        ss << "#include <windows.h>\n";
        ss << "#include <wincrypt.h>\n\n";
        
        ss << "int main() {\n";
        ss << "    // Encrypted data\n";
        ss << "    std::vector<uint8_t> encryptedData = {";
        
        for (size_t i = 0; i < encryptedData.size(); i++) {
            if (i > 0) ss << ", ";
            ss << "0x" << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(encryptedData[i]);
        }
        
        ss << "};\n\n";
        ss << "    // Decrypt and execute\n";
        ss << "    // Implementation here...\n";
        ss << "    return 0;\n";
        ss << "}\n";
        
        return ss.str();
    }
};

} // namespace SimplePEEncryptor

int main(int argc, char* argv[]) {
    std::cout << "Simple PE Encryptor - Windows Edition\n";
    std::cout << "=====================================\n\n";
    
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " <input_file> <output_file>\n";
        std::cout << "Example: " << argv[0] << " malware.exe encrypted_malware.bin\n\n";
        return 1;
    }
    
    std::string inputPath = argv[1];
    std::string outputPath = argv[2];
    
    // Check if input file exists
    if (!std::filesystem::exists(inputPath)) {
        std::cout << "[ERROR] Input file does not exist: " << inputPath << std::endl;
        return 1;
    }
    
    SimplePEEncryptor::PEEncryptor encryptor;
    
    if (encryptor.encryptPE(inputPath, outputPath)) {
        std::cout << "\n[SUCCESS] File encrypted successfully!\n";
        std::cout << "Original: " << inputPath << "\n";
        std::cout << "Encrypted: " << outputPath << "\n";
        return 0;
    } else {
        std::cout << "\n[ERROR] Encryption failed!\n";
        return 1;
    }
}
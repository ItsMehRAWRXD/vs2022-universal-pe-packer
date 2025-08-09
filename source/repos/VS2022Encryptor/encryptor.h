#pragma once
#include <vector>
#include <string>

class Encryptor {
public:
    virtual ~Encryptor() = default;
    virtual std::vector<unsigned char> encrypt(const std::vector<unsigned char>& data, const std::string& key) = 0;
    virtual std::vector<unsigned char> decrypt(const std::vector<unsigned char>& data, const std::string& key) = 0;
    
protected:
    std::vector<unsigned char> xorEncrypt(const std::vector<unsigned char>& data, const std::string& key);
    std::string generateRandomKey(size_t length);
};
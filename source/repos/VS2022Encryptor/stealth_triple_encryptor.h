#pragma once
#include "pe_encryptor.h"

class StealthTripleEncryptor : public PEEncryptor {
public:
    StealthTripleEncryptor();
    ~StealthTripleEncryptor();
    
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& data, const std::string& key) override;
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& data, const std::string& key) override;
    
    bool packWithStealth(const std::string& inputFile, const std::string& outputFile, const std::string& key);
    
private:
    std::vector<unsigned char> tripleEncrypt(const std::vector<unsigned char>& data, const std::string& key);
    std::vector<unsigned char> tripleDecrypt(const std::vector<unsigned char>& data, const std::string& key);
    std::vector<unsigned char> addAntiDebugFeatures(const std::vector<unsigned char>& data);
    std::vector<unsigned char> obfuscateHeaders(const std::vector<unsigned char>& data);
};
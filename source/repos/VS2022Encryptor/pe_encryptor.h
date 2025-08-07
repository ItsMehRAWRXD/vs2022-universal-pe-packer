#pragma once
#include "encryptor.h"
#include <cstdint>

class PEEncryptor : public Encryptor {
public:
    PEEncryptor();
    ~PEEncryptor();
    
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& data, const std::string& key) override;
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& data, const std::string& key) override;
    
    bool packPE(const std::string& inputFile, const std::string& outputFile, const std::string& key);
    bool unpackPE(const std::string& inputFile, const std::string& outputFile, const std::string& key);
    
protected:
    bool isValidPE(const std::vector<unsigned char>& data);
    std::vector<unsigned char> loadFile(const std::string& filename);
    bool saveFile(const std::string& filename, const std::vector<unsigned char>& data);
};
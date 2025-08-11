#ifdef _WIN32
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    if (CreateProcessA(tempFile.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    DeleteFileA(tempFile.c_str());
#else
    chmod(tempFile.c_str(), 0755);
    system(tempFile.c_str());
    unlink(tempFile.c_str());
#endif
    
    return 0;
})";

        // Save the packed executable source
        std::filesystem::path inputPath(inputFile);
        std::string outputFile = inputPath.stem().string() + "_packed.cpp";
        
        std::ofstream outFile(outputFile);
        if (!outFile) {
            std::cout << "❌ Error: Cannot create output file " << outputFile << std::endl;
            return;
        }

        outFile << sourceCode;
        outFile.close();

        std::cout << "✅ AES Packer generated successfully!" << std::endl;
        std::cout << "📁 Output: " << outputFile << std::endl;
        std::cout << "💾 Original size: " << fileData.size() << " bytes" << std::endl;
        std::cout << "🔐 Encrypted size: " << encryptedData.size() << " bytes" << std::endl;
        std::cout << "📋 Compile with: g++ -O2 " << outputFile << " -o " << inputPath.stem().string() << "_packed.exe" << std::endl;
        
        // Auto-compile the generated source file
        autoCompile(outputFile);
    }
    // ChaCha20 Packer (option 2) - Works like UPX
    void generateChaCha20Packer() {
        std::string inputFile;
        std::cout << "Enter input file path: ";
        std::getline(std::cin, inputFile);

        std::ifstream file(inputFile, std::ios::binary);
        if (!file) {
            std::cout << "❌ Error: Cannot open file " << inputFile << std::endl;
            return;
        }

        std::vector<uint8_t> fileData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        // Generate ChaCha20 key and nonce
        auto keys = generateKeys();
        std::vector<uint8_t> encryptedData = fileData;
        chacha20Crypt(encryptedData, keys.chacha_key.data(), keys.chacha_nonce.data());

        // Convert key and nonce to decimal for obfuscation
        std::string keyDecimal = bytesToBigDecimal(keys.chacha_key);
        std::string nonceDecimal = bytesToBigDecimal(keys.chacha_nonce);

        // Generate unique variable names
        std::string payloadVar = generateUniqueVarName();
        std::string keyVar = generateUniqueVarName();
        std::string nonceVar = generateUniqueVarName();
        std::string sizeVar = generateUniqueVarName();
        std::string bufferVar = generateUniqueVarName();
        std::string funcName = generateUniqueVarName();

        // Create the packed executable source
        std::string sourceCode = R"(#include <iostream>
#include <vector>
#include <fstream>
#include <cstring>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#include <cstdlib>
#endif

void quarterRound(unsigned int& a, unsigned int& b, unsigned int& c, unsigned int& d) {
    a += b; d ^= a; d = (d << 16) | (d >> 16);
    c += d; b ^= c; b = (b << 12) | (b >> 20);
    a += b; d ^= a; d = (d << 8) | (d >> 24);
    c += d; b ^= c; b = (b << 7) | (b >> 25);
}

void chachaBlock(unsigned int out[16], const unsigned int in[16]) {
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

void initChachaState(unsigned int state[16], const unsigned char key[32], const unsigned char nonce[12]) {
    const char* constants = "expand 32-byte k";
    memcpy(state, constants, 16);
    memcpy(state + 4, key, 32);
    state[12] = 0;
    memcpy(state + 13, nonce, 12);
}

void )" + funcName + R"((std::vector<unsigned char>& data, const unsigned char key[32], const unsigned char nonce[12]) {
    unsigned int state[16];
    initChachaState(state, key, nonce);
    
    for (size_t i = 0; i < data.size(); i += 64) {
        unsigned int keystream[16];
        chachaBlock(keystream, state);
        
        unsigned char* ks_bytes = (unsigned char*)keystream;
        for (size_t j = 0; j < 64 && i + j < data.size(); j++) {
            data[i + j] ^= ks_bytes[j];
        }
        
        state[12]++;
    }
}

std::vector<unsigned char> )" + keyVar + R"(FromDecimal(const std::string& decimal) {
    std::vector<unsigned char> result;
    std::vector<int> bigNum;
    
    for (char c : decimal) bigNum.push_back(c - '0');
    
    while (!bigNum.empty() && !(bigNum.size() == 1 && bigNum[0] == 0)) {
        int remainder = 0;
        for (size_t i = 0; i < bigNum.size(); i++) {
            int current = remainder * 10 + bigNum[i];
            bigNum[i] = current / 256;
            remainder = current % 256;
        }
        result.insert(result.begin(), remainder);
        while (!bigNum.empty() && bigNum[0] == 0) bigNum.erase(bigNum.begin());
    }
    
    return result;
}

int main() {
    const std::string )" + keyVar + R"( = ")" + keyDecimal + R"(";
    const std::string )" + nonceVar + R"( = ")" + nonceDecimal + R"(";
    const unsigned int )" + sizeVar + R"( = )" + std::to_string(encryptedData.size()) + R"(;
    
    unsigned char )" + payloadVar + R"([)" + std::to_string(encryptedData.size()) + R"(] = {)";

        // Embed the encrypted payload
        for (size_t i = 0; i < encryptedData.size(); i++) {
            if (i % 16 == 0) sourceCode += "\n        ";
            sourceCode += "0x" + 
                std::string(1, "0123456789ABCDEF"[(encryptedData[i] >> 4) & 0xF]) + 
                std::string(1, "0123456789ABCDEF"[encryptedData[i] & 0xF]);
            if (i < encryptedData.size() - 1) sourceCode += ",";
        }

        sourceCode += R"(
    };
    
    std::vector<unsigned char> )" + bufferVar + R"(()" + payloadVar + R"(, )" + payloadVar + R"( + )" + sizeVar + R"();
    std::vector<unsigned char> keyBytes = )" + keyVar + R"(FromDecimal()" + keyVar + R"();
    std::vector<unsigned char> nonceBytes = )" + keyVar + R"(FromDecimal()" + nonceVar + R"();
    
    )" + funcName + R"(()" + bufferVar + R"(, keyBytes.data(), nonceBytes.data());
    
#ifdef _WIN32
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string tempFile = std::string(tempPath) + "\\upx_temp_" + std::to_string(GetCurrentProcessId()) + ".exe";
#else
    std::string tempFile = "/tmp/upx_temp_" + std::to_string(getpid());
#endif
    
    std::ofstream outFile(tempFile, std::ios::binary);
    if (!outFile) return 1;
    
    outFile.write(reinterpret_cast<const char*>()" + bufferVar + R"(.data()), )" + bufferVar + R"(.size());
    outFile.close();
    
#ifdef _WIN32
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    if (CreateProcessA(tempFile.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    DeleteFileA(tempFile.c_str());
#else
    chmod(tempFile.c_str(), 0755);
    system(tempFile.c_str());
    unlink(tempFile.c_str());
#endif
    
    return 0;
})";

        // Save the packed executable source
        std::filesystem::path inputPath(inputFile);
        std::string outputFile = inputPath.stem().string() + "_chacha20_packed.cpp";
        
        std::ofstream outFile(outputFile);
        if (!outFile) {
            std::cout << "❌ Error: Cannot create output file " << outputFile << std::endl;
            return;
        }

        outFile << sourceCode;
        outFile.close();

        std::cout << "✅ ChaCha20 Packer generated successfully!" << std::endl;
        std::cout << "📁 Output: " << outputFile << std::endl;
        std::cout << "💾 Original size: " << fileData.size() << " bytes" << std::endl;
        std::cout << "🔐 Encrypted size: " << encryptedData.size() << " bytes" << std::endl;
        std::cout << "📋 Compile with: g++ -O2 " << outputFile << " -o " << inputPath.stem().string() << "_chacha20_packed.exe" << std::endl;
        
        // Auto-compile the generated source file
        autoCompile(outputFile);
    }

    // Triple Encryption Packer (option 3) - Maximum Security
    void generateTriplePacker() {
        std::string inputFile;
        std::cout << "Enter input file path: ";
        std::getline(std::cin, inputFile);

        std::ifstream file(inputFile, std::ios::binary);
        if (!file) {
            std::cout << "❌ Error: Cannot open file " << inputFile << std::endl;
            return;
        }

        std::vector<uint8_t> fileData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        // Generate all keys
        auto keys = generateKeys();
        std::vector<uint8_t> encryptedData = fileData;
        
        // Apply triple encryption with randomized order
        switch (keys.encryption_order) {
            case 0: // ChaCha20 -> AES -> XOR
                chacha20Crypt(encryptedData, keys.chacha_key.data(), keys.chacha_nonce.data());
                aesStreamCrypt(encryptedData, keys.aes_key);
                xorCrypt(encryptedData, keys.xor_key);
                break;
            case 1: // ChaCha20 -> XOR -> AES
                chacha20Crypt(encryptedData, keys.chacha_key.data(), keys.chacha_nonce.data());
                xorCrypt(encryptedData, keys.xor_key);
                aesStreamCrypt(encryptedData, keys.aes_key);
                break;
            case 2: // AES -> ChaCha20 -> XOR
                aesStreamCrypt(encryptedData, keys.aes_key);
                chacha20Crypt(encryptedData, keys.chacha_key.data(), keys.chacha_nonce.data());
                xorCrypt(encryptedData, keys.xor_key);
                break;
            case 3: // AES -> XOR -> ChaCha20
                aesStreamCrypt(encryptedData, keys.aes_key);
                xorCrypt(encryptedData, keys.xor_key);
                chacha20Crypt(encryptedData, keys.chacha_key.data(), keys.chacha_nonce.data());
                break;
            case 4: // XOR -> ChaCha20 -> AES
                xorCrypt(encryptedData, keys.xor_key);
                chacha20Crypt(encryptedData, keys.chacha_key.data(), keys.chacha_nonce.data());
                aesStreamCrypt(encryptedData, keys.aes_key);
                break;
            case 5: // XOR -> AES -> ChaCha20
                xorCrypt(encryptedData, keys.xor_key);
                aesStreamCrypt(encryptedData, keys.aes_key);
                chacha20Crypt(encryptedData, keys.chacha_key.data(), keys.chacha_nonce.data());
                break;
        }

        // Convert all keys to decimal for obfuscation
        std::string chachaKeyDecimal = bytesToBigDecimal(keys.chacha_key);
        std::string chachaNonceDecimal = bytesToBigDecimal(keys.chacha_nonce);
        std::string aesKeyDecimal = bytesToBigDecimal(keys.aes_key);
        std::string xorKeyDecimal = bytesToBigDecimal(keys.xor_key);

        // Generate unique variable names
        std::string payloadVar = generateUniqueVarName();
        std::string keyVar1 = generateUniqueVarName();
        std::string keyVar2 = generateUniqueVarName();
        std::string keyVar3 = generateUniqueVarName();
        std::string nonceVar = generateUniqueVarName();
        std::string sizeVar = generateUniqueVarName();
        std::string bufferVar = generateUniqueVarName();
        std::string funcName1 = generateUniqueVarName();
        std::string funcName2 = generateUniqueVarName();
        std::string funcName3 = generateUniqueVarName();

        // Create the packed executable source with all three algorithms
        std::string sourceCode = R"(#include <iostream>
#include <vector>
#include <fstream>
#include <cstring>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#include <cstdlib>
#endif

// ChaCha20 Implementation
void quarterRound(unsigned int& a, unsigned int& b, unsigned int& c, unsigned int& d) {
    a += b; d ^= a; d = (d << 16) | (d >> 16);

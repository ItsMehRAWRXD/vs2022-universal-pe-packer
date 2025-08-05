    void generateAESPacker() {
        std::cout << "\n🔐 AES Stream Cipher Packer\n";
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
        
        // Generate keys
        TripleKey keys = generateKeys();
        
        // Encrypt data
        aesStreamCrypt(data, keys.aes_key);
        
        // Generate polymorphic variable names
        std::string dataVar = generateUniqueVarName();
        std::string keyVar = generateUniqueVarName();
        std::string sizeVar = generateUniqueVarName();
        std::string outputVar = generateUniqueVarName();
        std::string fileVar = generateUniqueVarName();
        
        // Convert data to decimal string
        std::string dataStr = bytesToBigDecimal(data);
        std::string keyStr = bytesToBigDecimal(keys.aes_key);
        
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
        
        outFile << "// Encrypted payload data\n";
        outFile << "const std::string " << dataVar << " = \"" << dataStr << "\";\n";
        outFile << "const std::string " << keyVar << " = \"" << keyStr << "\";\n";
        outFile << "const size_t " << sizeVar << " = " << data.size() << ";\n\n";
        
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
        
        outFile << "// AES Stream decryption\n";
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
        
        outFile << "int main() {\n";
        outFile << "    std::cout << \"🔓 Decrypting and extracting: " << fileName << "\" << std::endl;\n\n";
        
        outFile << "    // Extract encrypted data\n";
        outFile << "    std::vector<uint8_t> " << outputVar << " = hexToBytes(" << dataVar << ");\n";
        outFile << "    std::vector<uint8_t> " << keyVar << "_bytes = hexToBytes(" << keyVar << ");\n\n";
        
        outFile << "    // Decrypt data\n";
        outFile << "    aesStreamDecrypt(" << outputVar << ", " << keyVar << "_bytes);\n\n";
        
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
        
        std::cout << "✅ AES Packer generated: " << outputFile << std::endl;
        std::cout << "📦 Payload size: " << data.size() << " bytes\n";
        std::cout << "🔐 Encryption: AES Stream Cipher\n";
        
        // Auto-compile the generated source
        autoCompile(outputFile);
    }
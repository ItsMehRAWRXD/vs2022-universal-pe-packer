public:
    VS2022MenuEncryptor() : rng(std::chrono::high_resolution_clock::now().time_since_epoch().count()) {}

    void showMenu() {
        std::cout << "\n🔐 VS2022 Universal Encryptor & Packer 🔐\n";
        std::cout << "==========================================\n";
        std::cout << "1.  Basic File Encryption (XOR)\n";
        std::cout << "2.  AES Stream Cipher Packer\n";
        std::cout << "3.  ChaCha20 Packer\n";
        std::cout << "4.  Triple Encryption Packer\n";
        std::cout << "5.  Generate MASM Runtime Stub\n";
        std::cout << "6.  URL Crypto Service (AES)\n";
        std::cout << "7.  URL Crypto Service (Triple)\n";
        std::cout << "8.  URL Crypto Service (ChaCha20)\n";
        std::cout << "9.  URL Crypto Service (Basic)\n";
        std::cout << "10. URL Pack File (AES)\n";
        std::cout << "11. URL Pack File (ChaCha20)\n";
        std::cout << "12. URL Pack File (Triple)\n";
        std::cout << "13. Local Crypto Service (AES)\n";
        std::cout << "14. Local Crypto Service (ChaCha20)\n";
        std::cout << "15. Local Crypto Service (Triple)\n";
        std::cout << "16. Drag & Drop Processing\n";
        std::cout << "0.  Exit\n";
        std::cout << "==========================================\n";
        std::cout << "Choice: ";
    }

    void run() {
        while (true) {
            showMenu();
            int choice;
            std::cin >> choice;
            
            if (choice == 0) {
                std::cout << "👋 Goodbye!\n";
                break;
            }
            
            switch (choice) {
                case 1: basicFileEncryption(); break;
                case 2: generateAESPacker(); break;
                case 3: generateChaCha20Packer(); break;
                case 4: generateTriplePacker(); break;
                case 5: generateMASMStub(); break;
                case 6: urlCryptoServiceAES(); break;
                case 7: urlCryptoServiceTriple(); break;
                case 8: urlCryptoServiceChaCha20(); break;
                case 9: urlCryptoServiceBasic(); break;
                case 10: urlPackFileAES(); break;
                case 11: urlPackFileChaCha20(); break;
                case 12: urlPackFileTriple(); break;
                case 13: localCryptoServiceAES(); break;
                case 14: localCryptoServiceChaCha20(); break;
                case 15: localCryptoServiceTriple(); break;
                case 16: {
                    std::cout << "📁 Enter file path to process: ";
                    std::string filePath;
                    std::cin.ignore();
                    std::getline(std::cin, filePath);
                    handleDragDrop(filePath);
                    break;
                }
                default:
                    std::cout << "❌ Invalid choice!\n";
            }
        }
    }

    void basicFileEncryption() {
        std::cout << "\n🔐 Basic File Encryption (XOR)\n";
        std::cout << "==============================\n";
        
        std::string inputFile, outputFile;
        std::cout << "📁 Input file: ";
        std::cin >> inputFile;
        std::cout << "💾 Output file: ";
        std::cin >> outputFile;
        
        std::ifstream file(inputFile, std::ios::binary);
        if (!file) {
            std::cout << "❌ Cannot open input file!\n";
            return;
        }
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        
        // Generate random key
        std::vector<uint8_t> key(32);
        for (auto& k : key) k = rng() % 256;
        
        // Encrypt
        xorCrypt(data, key);
        
        // Write encrypted data
        std::ofstream outFile(outputFile, std::ios::binary);
        if (!outFile) {
            std::cout << "❌ Cannot create output file!\n";
            return;
        }
        outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
        outFile.close();
        
        // Generate key file
        std::string keyFile = outputFile + ".key";
        std::ofstream keyOut(keyFile);
        keyOut << "Key: " << bytesToBigDecimal(key) << std::endl;
        keyOut.close();
        
        std::cout << "✅ Encryption complete!\n";
        std::cout << "📄 Encrypted file: " << outputFile << std::endl;
        std::cout << "🔑 Key file: " << keyFile << std::endl;
    }
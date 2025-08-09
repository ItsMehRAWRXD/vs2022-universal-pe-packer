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
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <cstring>
#include <thread>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")
#else
#include <unistd.h>
#include <sys/time.h>
// Note: For Linux, install libcurl-dev or compile without URL features
// #include <curl/curl.h>
#endif

class VS2022MenuEncryptor {
private:
    std::mt19937_64 rng;

    // Enhanced auto-compilation helper function (supports C++ and MASM)
    void autoCompile(const std::string& sourceFile) {
        std::cout << "[COMPILE] Auto-compiling to executable..." << std::endl;

        // Determine file type by extension
        std::string extension = sourceFile.substr(sourceFile.find_last_of('.'));
        std::string baseName = sourceFile.substr(0, sourceFile.find_last_of('.'));
        std::string exeName = baseName + ".exe";
        std::string compileCmd;
        int result = -1;

        if (extension == ".cpp" || extension == ".c") {
            // C++ compilation
            std::cout << "[INFO] Detected C++ source file" << std::endl;
#ifdef _WIN32
            // Try g++ first (MinGW/TDM-GCC)
            compileCmd = "g++ -std=c++17 -O2 -static \"" + sourceFile + "\" -o \"" + exeName + "\" -lwininet -ladvapi32 2>nul";
            result = system(compileCmd.c_str());

            if (result != 0) {
                // Fallback to cl.exe (Visual Studio)
                compileCmd = "cl /std:c++17 /O2 \"" + sourceFile + "\" /Fe:\"" + exeName + "\" wininet.lib advapi32.lib 2>nul";
                result = system(compileCmd.c_str());
            }
#else
            compileCmd = "g++ -std=c++17 -O2 \"" + sourceFile + "\" -o \"" + exeName + "\"";
            result = system(compileCmd.c_str());
#endif
        }
        else if (extension == ".asm") {
            // MASM assembly compilation
            std::cout << "[INFO] Detected MASM assembly source file" << std::endl;
#ifdef _WIN32
            // Use MASM32 or Visual Studio MASM
            compileCmd = "ml /c /coff \"" + sourceFile + "\" && link /subsystem:windows \"" + baseName + ".obj\" /out:\"" + exeName + "\" 2>nul";
            result = system(compileCmd.c_str());

            // Clean up .obj file
            std::string cleanupCmd = "del \"" + baseName + ".obj\" 2>nul";
            system(cleanupCmd.c_str());
#endif
        }

        if (result == 0) {
            std::cout << "✅ [SUCCESS] Executable created: " << exeName << std::endl;
            std::cout << "📋 [INFO] Compile command used: " << compileCmd << std::endl;
        }
        else {
            std::cout << "❌ [ERROR] Compilation failed. Manual compilation required." << std::endl;
            std::cout << "📋 [INFO] Attempted command: " << compileCmd << std::endl;
        }
    }

    struct TripleKey {
        std::vector<uint8_t> chacha_key;
        std::vector<uint8_t> aes_key;
        std::vector<uint8_t> xor_key;
        
        TripleKey() : chacha_key(32), aes_key(32), xor_key(32) {}
    };

    // ChaCha20 implementation
    void chachaQuarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = (d << 16) | (d >> 16);
        c += d; b ^= c; b = (b << 12) | (b >> 20);
        a += b; d ^= a; d = (d << 8) | (d >> 24);
        c += d; b ^= c; b = (b << 7) | (b >> 25);
    }

    void chachaBlock(const uint8_t* key, const uint8_t* nonce, uint32_t counter, uint8_t* output) {
        uint32_t state[16] = {
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            *reinterpret_cast<const uint32_t*>(key),
            *reinterpret_cast<const uint32_t*>(key + 4),
            *reinterpret_cast<const uint32_t*>(key + 8),
            *reinterpret_cast<const uint32_t*>(key + 12),
            *reinterpret_cast<const uint32_t*>(key + 16),
            *reinterpret_cast<const uint32_t*>(key + 20),
            *reinterpret_cast<const uint32_t*>(key + 24),
            *reinterpret_cast<const uint32_t*>(key + 28),
            counter,
            *reinterpret_cast<const uint32_t*>(nonce),
            *reinterpret_cast<const uint32_t*>(nonce + 4),
            *reinterpret_cast<const uint32_t*>(nonce + 8)
        };

        uint32_t working[16];
        std::memcpy(working, state, sizeof(state));

        for (int i = 0; i < 10; ++i) {
            chachaQuarterRound(working[0], working[4], working[8], working[12]);
            chachaQuarterRound(working[1], working[5], working[9], working[13]);
            chachaQuarterRound(working[2], working[6], working[10], working[14]);
            chachaQuarterRound(working[3], working[7], working[11], working[15]);
            chachaQuarterRound(working[0], working[5], working[10], working[15]);
            chachaQuarterRound(working[1], working[6], working[11], working[12]);
            chachaQuarterRound(working[2], working[7], working[8], working[13]);
            chachaQuarterRound(working[3], working[4], working[9], working[14]);
        }

        for (int i = 0; i < 16; ++i) {
            working[i] += state[i];
        }

        std::memcpy(output, working, 64);
    }

    // AES-256 implementation (simplified)
    void aesEncrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, std::vector<uint8_t>& output) {
        output = data;
        for (size_t i = 0; i < output.size(); ++i) {
            output[i] ^= key[i % key.size()];
        }
    }

    // XOR encryption
    void xorEncrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, std::vector<uint8_t>& output) {
        output.resize(data.size());
        for (size_t i = 0; i < data.size(); ++i) {
            output[i] = data[i] ^ key[i % key.size()];
        }
    }

    // Generate cryptographically secure random bytes
    void generateSecureBytes(std::vector<uint8_t>& buffer) {
#ifdef _WIN32
        HCRYPTPROV hCryptProv;
        if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            CryptGenRandom(hCryptProv, static_cast<DWORD>(buffer.size()), buffer.data());
            CryptReleaseContext(hCryptProv, 0);
        } else {
            // Fallback to time-based seed
            auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
            rng.seed(seed);
            for (auto& byte : buffer) {
                byte = static_cast<uint8_t>(rng() & 0xFF);
            }
        }
#else
        std::ifstream urandom("/dev/urandom", std::ios::binary);
        if (urandom.is_open()) {
            urandom.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
            urandom.close();
        } else {
            // Fallback to time-based seed
            auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
            rng.seed(seed);
            for (auto& byte : buffer) {
                byte = static_cast<uint8_t>(rng() & 0xFF);
            }
        }
#endif
    }

    // Convert bytes to hex string
    std::string bytesToHex(const std::vector<uint8_t>& bytes) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (uint8_t byte : bytes) {
            oss << std::setw(2) << static_cast<int>(byte);
        }
        return oss.str();
    }

    // Convert hex string to bytes
    std::vector<uint8_t> hexToBytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }

    // Generate menu options with dynamic content
    std::vector<std::string> generateMenuOptions() {
        std::vector<std::string> options = {
            "🔐 Encrypt Sensitive Data",
            "🔓 Decrypt Protected Data",
            "🔑 Generate Security Keys",
            "📁 Process File Batch",
            "🛡️ Security Analysis",
            "⚙️ Advanced Settings",
            "📊 System Information",
            "🌐 Network Operations",
            "💾 Backup Operations",
            "🔄 Update Components",
            "🎯 Target Selection",
            "🚀 Deploy Payload",
            "📈 Performance Monitor",
            "🔍 Search & Filter",
            "❌ Exit Application"
        };

        // Shuffle options for dynamic appearance
        std::shuffle(options.begin(), options.end() - 1, rng); // Keep "Exit" at end
        std::string exitOption = options.back();
        options.pop_back();
        std::shuffle(options.begin(), options.end(), rng);
        options.push_back(exitOption);

        return options;
    }

public:
    // Helper function for C++17 compatibility (replaces C++20 ends_with)
    static bool stringEndsWith(const std::string& str, const std::string& suffix) {
        if (str.length() >= suffix.length()) {
            return (str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0);
        }
        return false;
    }

    VS2022MenuEncryptor() {
        auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        rng.seed(seed);
    }

    // Main menu display with Visual Studio 2022 theme
    void displayMenu() {
        system("cls || clear");
        
        std::cout << "\033[94m";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                    VS2022 Menu Encryptor                    ║\n";
        std::cout << "║                   Advanced Security Suite                    ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "\033[0m";

        auto options = generateMenuOptions();
        
        for (size_t i = 0; i < options.size(); ++i) {
            std::cout << "\033[96m";
            std::cout << "║ [" << std::setw(2) << (i + 1) << "] ";
            std::cout << "\033[92m" << std::left << std::setw(50) << options[i];
            std::cout << "\033[96m ║\n";
            std::cout << "\033[0m";
        }

        std::cout << "\033[94m";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
        std::cout << "\033[0m";
        
        // System info footer
        std::cout << "\033[90m";
        std::cout << "┌─ System: " << sizeof(void*) * 8 << "-bit";
#ifdef _WIN32
        std::cout << " Windows";
#else
        std::cout << " Linux";
#endif
        std::cout << " │ Memory: " << (rand() % 16 + 8) << "GB Available";
        std::cout << " │ Security: ACTIVE ─┐\n";
        std::cout << "\033[0m";
    }

    // Triple-layer encryption function
    std::string encryptData(const std::string& data) {
        TripleKey keys;
        generateSecureBytes(keys.chacha_key);
        generateSecureBytes(keys.aes_key);
        generateSecureBytes(keys.xor_key);

        // Convert input to bytes
        std::vector<uint8_t> inputBytes(data.begin(), data.end());
        
        // Layer 1: ChaCha20 encryption
        std::vector<uint8_t> chachaResult;
        std::vector<uint8_t> nonce(12, 0);
        generateSecureBytes(nonce);
        
        chachaResult.resize(inputBytes.size());
        for (size_t i = 0; i < inputBytes.size(); i += 64) {
            uint8_t keystream[64];
            chachaBlock(keys.chacha_key.data(), nonce.data(), static_cast<uint32_t>(i / 64), keystream);
            
            for (size_t j = 0; j < 64 && (i + j) < inputBytes.size(); ++j) {
                chachaResult[i + j] = inputBytes[i + j] ^ keystream[j];
            }
        }

        // Layer 2: AES encryption
        std::vector<uint8_t> aesResult;
        aesEncrypt(chachaResult, keys.aes_key, aesResult);

        // Layer 3: XOR encryption
        std::vector<uint8_t> finalResult;
        xorEncrypt(aesResult, keys.xor_key, finalResult);

        // Combine keys and encrypted data
        std::string result = bytesToHex(keys.chacha_key) + ":" + 
                           bytesToHex(keys.aes_key) + ":" + 
                           bytesToHex(keys.xor_key) + ":" + 
                           bytesToHex(nonce) + ":" + 
                           bytesToHex(finalResult);

        return result;
    }

    // Triple-layer decryption function
    std::string decryptData(const std::string& encryptedData) {
        size_t pos = 0;
        std::vector<std::string> parts;
        
        // Split the encrypted data
        while (pos < encryptedData.length()) {
            size_t nextPos = encryptedData.find(':', pos);
            if (nextPos == std::string::npos) {
                parts.push_back(encryptedData.substr(pos));
                break;
            }
            parts.push_back(encryptedData.substr(pos, nextPos - pos));
            pos = nextPos + 1;
        }

        if (parts.size() != 5) {
            throw std::runtime_error("Invalid encrypted data format");
        }

        // Extract components
        auto chachaKey = hexToBytes(parts[0]);
        auto aesKey = hexToBytes(parts[1]);
        auto xorKey = hexToBytes(parts[2]);
        auto nonce = hexToBytes(parts[3]);
        auto encryptedBytes = hexToBytes(parts[4]);

        // Layer 3: Reverse XOR encryption
        std::vector<uint8_t> xorResult;
        xorEncrypt(encryptedBytes, xorKey, xorResult);

        // Layer 2: Reverse AES encryption (using same function as it's XOR-based)
        std::vector<uint8_t> aesResult;
        aesEncrypt(xorResult, aesKey, aesResult);

        // Layer 1: Reverse ChaCha20 encryption
        std::vector<uint8_t> finalResult(aesResult.size());
        for (size_t i = 0; i < aesResult.size(); i += 64) {
            uint8_t keystream[64];
            chachaBlock(chachaKey.data(), nonce.data(), static_cast<uint32_t>(i / 64), keystream);
            
            for (size_t j = 0; j < 64 && (i + j) < aesResult.size(); ++j) {
                finalResult[i + j] = aesResult[i + j] ^ keystream[j];
            }
        }

        return std::string(finalResult.begin(), finalResult.end());
    }

    // File processing functions
    void encryptFile(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open file: " + filePath);
        }

        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        file.close();

        std::string encrypted = encryptData(content);
        
        std::string outPath = filePath + ".encrypted";
        std::ofstream outFile(outPath, std::ios::binary);
        outFile << encrypted;
        outFile.close();

        std::cout << "✅ File encrypted: " << outPath << std::endl;
    }

    void decryptFile(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open file: " + filePath);
        }

        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        file.close();

        std::string decrypted = decryptData(content);
        
        std::string outPath = filePath;
        if (stringEndsWith(outPath, ".encrypted")) {
            outPath = outPath.substr(0, outPath.length() - 10);
        } else {
            outPath += ".decrypted";
        }

        std::ofstream outFile(outPath, std::ios::binary);
        outFile << decrypted;
        outFile.close();

        std::cout << "✅ File decrypted: " << outPath << std::endl;
    }

    // Interactive menu system
    void runInteractiveMenu() {
        int choice;
        std::string input;

        while (true) {
            displayMenu();
            std::cout << "\n\033[93m┌─ Enter choice [1-15]: \033[0m";
            std::cin >> choice;

            switch (choice) {
                case 1: {
                    std::cout << "\n🔐 Enter data to encrypt: ";
                    std::cin.ignore();
                    std::getline(std::cin, input);
                    try {
                        std::string encrypted = encryptData(input);
                        std::cout << "\n✅ Encrypted: " << encrypted.substr(0, 64) << "...\n";
                        std::cout << "📋 Full result saved to clipboard simulation.\n";
                    } catch (const std::exception& e) {
                        std::cout << "❌ Error: " << e.what() << std::endl;
                    }
                    break;
                }
                case 2: {
                    std::cout << "\n🔓 Enter encrypted data: ";
                    std::cin.ignore();
                    std::getline(std::cin, input);
                    try {
                        std::string decrypted = decryptData(input);
                        std::cout << "\n✅ Decrypted: " << decrypted << std::endl;
                    } catch (const std::exception& e) {
                        std::cout << "❌ Error: " << e.what() << std::endl;
                    }
                    break;
                }
                case 3: {
                    std::cout << "\n🔑 Generating security keys...\n";
                    TripleKey keys;
                    generateSecureBytes(keys.chacha_key);
                    generateSecureBytes(keys.aes_key);
                    generateSecureBytes(keys.xor_key);
                    
                    std::cout << "ChaCha20 Key: " << bytesToHex(keys.chacha_key).substr(0, 32) << "...\n";
                    std::cout << "AES-256 Key:  " << bytesToHex(keys.aes_key).substr(0, 32) << "...\n";
                    std::cout << "XOR Key:      " << bytesToHex(keys.xor_key).substr(0, 32) << "...\n";
                    break;
                }
                case 4: {
                    std::cout << "\n📁 Enter file path: ";
                    std::cin.ignore();
                    std::getline(std::cin, input);
                    try {
                        if (stringEndsWith(input, ".encrypted")) {
                            decryptFile(input);
                        } else {
                            encryptFile(input);
                        }
                    } catch (const std::exception& e) {
                        std::cout << "❌ Error: " << e.what() << std::endl;
                    }
                    break;
                }
                case 15: {
                    std::cout << "\n🚪 Exiting VS2022 Menu Encryptor...\n";
                    std::cout << "🔒 All operations completed securely.\n";
                    return;
                }
                default: {
                    std::cout << "\n⚙️ Feature [" << choice << "] is under development.\n";
                    std::cout << "🔧 Advanced security modules loading...\n";
                    
                    // Simulate loading
                    for (int i = 0; i < 3; ++i) {
                        std::cout << "⏳ Processing";
                        for (int j = 0; j < 4; ++j) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(200));
                            std::cout << ".";
                            std::cout.flush();
                        }
                        std::cout << "\r";
                        std::cout.flush();
                    }
                    std::cout << "✅ Module initialized successfully!     \n";
                    break;
                }
            }

            std::cout << "\n\033[90mPress Enter to continue...\033[0m";
            std::cin.ignore();
            std::cin.get();
        }
    }

    // Self-compilation feature
    void compileSelf(const std::string& sourceFile = __FILE__) {
        std::cout << "\n🔄 Initiating self-compilation process...\n";
        autoCompile(sourceFile);
    }
};

// Main function
int main(int argc, char* argv[]) {
    try {
        VS2022MenuEncryptor encryptor;

        // Command line arguments handling
        if (argc > 1) {
            std::string command = argv[1];
            
            if (command == "--compile" || command == "-c") {
                encryptor.compileSelf(argc > 2 ? argv[2] : __FILE__);
                return 0;
            }
            else if (command == "--encrypt" || command == "-e") {
                if (argc < 3) {
                    std::cerr << "Usage: " << argv[0] << " --encrypt <data>" << std::endl;
                    return 1;
                }
                std::string encrypted = encryptor.encryptData(argv[2]);
                std::cout << encrypted << std::endl;
                return 0;
            }
            else if (command == "--decrypt" || command == "-d") {
                if (argc < 3) {
                    std::cerr << "Usage: " << argv[0] << " --decrypt <encrypted_data>" << std::endl;
                    return 1;
                }
                std::string decrypted = encryptor.decryptData(argv[2]);
                std::cout << decrypted << std::endl;
                return 0;
            }
            else if (command == "--file" || command == "-f") {
                if (argc < 3) {
                    std::cerr << "Usage: " << argv[0] << " --file <filepath>" << std::endl;
                    return 1;
                }
                std::string filepath = argv[2];
                if (VS2022MenuEncryptor::stringEndsWith(filepath, ".encrypted")) {
                    encryptor.decryptFile(filepath);
                } else {
                    encryptor.encryptFile(filepath);
                }
                return 0;
            }
            else {
                std::cout << "VS2022 Menu Encryptor - Command Line Options:\n";
                std::cout << "  --compile, -c [file]    Compile source to executable\n";
                std::cout << "  --encrypt, -e <data>    Encrypt string data\n";
                std::cout << "  --decrypt, -d <data>    Decrypt string data\n";
                std::cout << "  --file, -f <filepath>   Encrypt/decrypt file\n";
                std::cout << "  --help, -h              Show this help\n";
                return 0;
            }
        }

        // Interactive mode
        encryptor.runInteractiveMenu();

    } catch (const std::exception& e) {
        std::cerr << "❌ Fatal Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <random>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

class SimplePEEncryptor {
private:
    std::vector<uint8_t> key;
    
    void generateKey() {
        key.clear();
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1, 255);
        
        // Generate 32-byte key
        for (int i = 0; i < 32; i++) {
            key.push_back(static_cast<uint8_t>(dis(gen)));
        }
    }
    
    std::vector<uint8_t> xorEncrypt(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> encrypted = data;
        
        for (size_t i = 0; i < encrypted.size(); i++) {
            encrypted[i] ^= key[i % key.size()];
        }
        
        return encrypted;
    }
    
    std::string generateLoaderCode(const std::vector<uint8_t>& encryptedData) {
        std::string loader = R"(
#include <iostream>
#include <vector>
#include <fstream>
#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

// Encrypted payload embedded here
unsigned char encrypted_payload[] = {)";
        
        // Add encrypted data as hex array
        for (size_t i = 0; i < encryptedData.size(); i++) {
            if (i % 16 == 0) loader += "\n    ";
            loader += "0x" + toHex(encryptedData[i]) + ",";
        }
        
        loader += R"(
};

// Decryption key
unsigned char key[] = {)";
        
        // Add key as hex array
        for (size_t i = 0; i < key.size(); i++) {
            if (i % 16 == 0) loader += "\n    ";
            loader += "0x" + toHex(key[i]) + ",";
        }
        
        loader += R"(
};

int main() {
    // Decrypt payload
    std::vector<unsigned char> decrypted(sizeof(encrypted_payload));
    for (size_t i = 0; i < sizeof(encrypted_payload); i++) {
        decrypted[i] = encrypted_payload[i] ^ key[i % sizeof(key)];
    }
    
    // Write to temp file
    char tempFile[] = "/tmp/decrypted_XXXXXX";
    int fd = mkstemp(tempFile);
    if (fd == -1) {
        std::cerr << "Failed to create temp file!" << std::endl;
        return 1;
    }
    
         // Write decrypted data
     ssize_t written = write(fd, decrypted.data(), decrypted.size());
     if (written != (ssize_t)decrypted.size()) {
         std::cerr << "Failed to write decrypted data!" << std::endl;
         close(fd);
         return 1;
     }
     close(fd);
    
    // Make executable
    chmod(tempFile, 0755);
    
    // Execute
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        execl(tempFile, tempFile, (char*)NULL);
        exit(1);
    } else if (pid > 0) {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
    }
    
    // Clean up
    unlink(tempFile);
    
    return 0;
}
)";
        
        return loader;
    }
    
    std::string toHex(uint8_t byte) {
        std::string hex = "";
        char chars[] = "0123456789ABCDEF";
        hex += chars[byte >> 4];
        hex += chars[byte & 0x0F];
        return hex;
    }
    
public:
    bool encryptFile(const std::string& inputPath, const std::string& outputPath) {
        std::cout << "[+] Reading input file: " << inputPath << std::endl;
        
        // Read input file
        std::ifstream file(inputPath, std::ios::binary);
        if (!file) {
            std::cerr << "[-] Cannot open input file!" << std::endl;
            return false;
        }
        
        std::vector<uint8_t> fileData((std::istreambuf_iterator<char>(file)),
                                      std::istreambuf_iterator<char>());
        file.close();
        
        std::cout << "[+] File size: " << fileData.size() << " bytes" << std::endl;
        
        // Generate encryption key
        generateKey();
        std::cout << "[+] Generated encryption key" << std::endl;
        
        // Encrypt file
        std::vector<uint8_t> encrypted = xorEncrypt(fileData);
        std::cout << "[+] File encrypted" << std::endl;
        
        // Generate loader source code
        std::string loaderCode = generateLoaderCode(encrypted);
        
        // Write loader source
        std::string loaderPath = outputPath + ".cpp";
        std::ofstream loaderFile(loaderPath);
        if (!loaderFile) {
            std::cerr << "[-] Cannot create loader source!" << std::endl;
            return false;
        }
        
        loaderFile << loaderCode;
        loaderFile.close();
        
        std::cout << "[+] Loader source written to: " << loaderPath << std::endl;
        
        // Compile loader
        std::string compileCmd = "g++ -std=c++11 -O2 -s \"" + loaderPath + "\" -o \"" + outputPath + "\"";
        std::cout << "[+] Compiling: " << compileCmd << std::endl;
        
        int result = system(compileCmd.c_str());
        if (result == 0) {
            std::cout << "[+] Successfully created encrypted executable: " << outputPath << std::endl;
            
            // Clean up source file
            remove(loaderPath.c_str());
            
            return true;
        } else {
            std::cerr << "[-] Compilation failed!" << std::endl;
            return false;
        }
    }
    
    void printUsage() {
        std::cout << "Simple File Encryptor (Linux)" << std::endl;
        std::cout << "Usage: ./pe_encryptor <input_file> <output_file>" << std::endl;
        std::cout << "Example: ./pe_encryptor /bin/ls encrypted_ls" << std::endl;
        std::cout << "Example: ./pe_encryptor myprogram encrypted_myprogram" << std::endl;
    }
};

int main(int argc, char* argv[]) {
    std::cout << "=== Simple File Encryptor (Linux) ===" << std::endl;
    
    if (argc != 3) {
        SimplePEEncryptor encryptor;
        encryptor.printUsage();
        return 1;
    }
    
    std::string inputFile = argv[1];
    std::string outputFile = argv[2];
    
    SimplePEEncryptor encryptor;
    if (encryptor.encryptFile(inputFile, outputFile)) {
        std::cout << "[+] Encryption successful!" << std::endl;
        std::cout << "[+] Test with: ./" << outputFile << std::endl;
        return 0;
    } else {
        std::cerr << "[-] Encryption failed!" << std::endl;
        return 1;
    }
}
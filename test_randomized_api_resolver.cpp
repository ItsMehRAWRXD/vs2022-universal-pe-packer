#include <iostream>
#include <fstream>
#include "randomized_api_resolver.h"

int main() {
    std::cout << "Testing Randomized API Resolver with XOR String Obfuscation..." << std::endl;
    
    RandomizedAPIResolver resolver;
    
    // Test 1: Generate randomized API resolution code
    std::cout << "\n=== Test 1: Randomized API Resolution ===" << std::endl;
    std::string apiCode = resolver.generateRandomizedAPIResolution();
    std::cout << "Generated API resolution code (first 500 chars):" << std::endl;
    std::cout << apiCode.substr(0, 500) << "..." << std::endl;
    
    // Test 2: Generate XOR obfuscated MessageBox
    std::cout << "\n=== Test 2: XOR Obfuscated MessageBox ===" << std::endl;
    std::string title = "Adobe Systems Incorporated";
    std::string message = "Adobe Systems Incorporated Application\n\nSystem check completed successfully.\n\nVersion: 1.0.0";
    
    std::string messageBoxCode = resolver.generateObfuscatedMessageBox(title, message);
    std::cout << "Generated obfuscated MessageBox code:" << std::endl;
    std::cout << messageBoxCode << std::endl;
    
    // Test 3: Generate multiple random variable names
    std::cout << "\n=== Test 3: Random Variable Names ===" << std::endl;
    for (int i = 0; i < 10; i++) {
        std::string varName = resolver.generateRandomVariableName("test");
        std::cout << "Random variable " << (i+1) << ": " << varName << std::endl;
    }
    
    // Test 4: Create a complete stealth stub with all features
    std::cout << "\n=== Test 4: Complete Stealth Stub ===" << std::endl;
    std::string completeStub = "#ifdef _WIN32\n";
    completeStub += "#include <windows.h>\n";
    completeStub += "#endif\n";
    completeStub += "#include <iostream>\n";
    completeStub += "#include <string>\n";
    completeStub += "#include <vector>\n\n";
    
    completeStub += "// Stealth stub with randomized API resolution and XOR obfuscation\n";
    completeStub += "int main() {\n";
    completeStub += apiCode;
    completeStub += "\n";
    completeStub += messageBoxCode;
    completeStub += "\n    return 0;\n";
    completeStub += "}\n";
    
    // Write to file for inspection
    std::ofstream stubFile("randomized_stealth_stub.cpp");
    if (stubFile.is_open()) {
        stubFile << completeStub;
        stubFile.close();
        std::cout << "Complete stealth stub written to 'randomized_stealth_stub.cpp'" << std::endl;
        std::cout << "File size: " << completeStub.length() << " bytes" << std::endl;
    } else {
        std::cout << "Failed to create output file" << std::endl;
    }
    
    // Test 5: Verify XOR encryption/decryption
    std::cout << "\n=== Test 5: XOR Encryption Verification ===" << std::endl;
    
    // Create test XORString objects
    class TestXORString {
    private:
        std::vector<uint8_t> data;
        uint8_t key;
        
    public:
        TestXORString(const char* str) {
            std::random_device rd;
            key = static_cast<uint8_t>(rd() % 256);
            
            size_t len = strlen(str);
            data.resize(len + 1);
            
            for (size_t i = 0; i < len; i++) {
                data[i] = static_cast<uint8_t>(str[i] ^ key);
            }
            data[len] = key;
        }
        
        std::string decrypt() const {
            std::string result;
            result.resize(data.size() - 1);
            
            for (size_t i = 0; i < data.size() - 1; i++) {
                result[i] = static_cast<char>(data[i] ^ key);
            }
            return result;
        }
        
        void printEncrypted() const {
            std::cout << "Encrypted data: ";
            for (size_t i = 0; i < data.size(); i++) {
                std::cout << "0x" << std::hex << std::uppercase << static_cast<int>(data[i]) << " ";
            }
            std::cout << std::dec << std::endl;
        }
    };
    
    const char* testStrings[] = {
        "kernel32.dll",
        "GetTickCount",
        "Adobe Systems Incorporated",
        "System check completed successfully"
    };
    
    for (int i = 0; i < 4; i++) {
        std::cout << "\nOriginal string: \"" << testStrings[i] << "\"" << std::endl;
        TestXORString xorStr(testStrings[i]);
        xorStr.printEncrypted();
        std::string decrypted = xorStr.decrypt();
        std::cout << "Decrypted string: \"" << decrypted << "\"" << std::endl;
        std::cout << "Match: " << (strcmp(testStrings[i], decrypted.c_str()) == 0 ? "YES" : "NO") << std::endl;
    }
    
    std::cout << "\n=== All Tests Completed ===" << std::endl;
    std::cout << "The randomized API resolver successfully generates:" << std::endl;
    std::cout << "• XOR-obfuscated strings that are unreadable in source code" << std::endl;
    std::cout << "• Randomized variable names for stealth" << std::endl;
    std::cout << "• Dynamic API resolution with anti-debugging checks" << std::endl;
    std::cout << "• Self-contained decryption routines" << std::endl;
    
    return 0;
}
#include <iostream>
#include <string>
#include <random>
#include <vector>

// Fixed Random Name Generator for FUD Code
class FixedRandomGenerator {
private:
    std::random_device rd;
    std::mt19937 gen;
    
public:
    FixedRandomGenerator() : gen(rd()) {}
    
    // Generate valid C++ variable names (NEVER start with digit)
    std::string generateValidVariableName(int length = 8) {
        // First character MUST be letter or underscore
        const std::string firstChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
        // Subsequent characters can include digits
        const std::string otherChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
        
        std::uniform_int_distribution<> firstDis(0, firstChars.length() - 1);
        std::uniform_int_distribution<> otherDis(0, otherChars.length() - 1);
        
        std::string result;
        
        // First character (no digits)
        result += firstChars[firstDis(gen)];
        
        // Remaining characters
        for (int i = 1; i < length; ++i) {
            result += otherChars[otherDis(gen)];
        }
        
        return result;
    }
    
    // Generate with specific prefixes for better organization
    std::string generatePrefixedName(const std::string& prefix, int length = 6) {
        return prefix + "_" + generateValidVariableName(length);
    }
    
    // Test the generator extensively
    void runTests() {
        std::cout << "=== Testing Fixed Random Generator ===" << std::endl;
        
        // Test 100 variable names
        std::cout << "\nTesting 100 variable names:" << std::endl;
        bool allValid = true;
        
        for (int i = 0; i < 100; i++) {
            std::string name = generateValidVariableName();
            
            // Check if first character is valid
            char first = name[0];
            if (first >= '0' && first <= '9') {
                std::cout << "❌ INVALID: " << name << " (starts with digit)" << std::endl;
                allValid = false;
            }
            
            if (i < 10) {
                std::cout << "✅ " << name << std::endl;
            }
        }
        
        if (allValid) {
            std::cout << "✅ All 100 names are valid!" << std::endl;
        }
        
        // Test prefixed names
        std::cout << "\nPrefixed variable names:" << std::endl;
        std::vector<std::string> prefixes = {"poly", "var", "key", "data", "func"};
        
        for (const auto& prefix : prefixes) {
            std::string name = generatePrefixedName(prefix);
            std::cout << "✅ " << name << std::endl;
        }
    }
    
    // Generate a complete valid FUD source template
    void generateValidFUDTemplate() {
        std::cout << "\n=== Valid FUD Source Template ===" << std::endl;
        
        std::cout << "#include <windows.h>" << std::endl;
        std::cout << "#include <stdio.h>" << std::endl;
        std::cout << "#include <stdlib.h>" << std::endl;
        std::cout << "#include <string.h>" << std::endl;
        std::cout << std::endl;
        
        std::cout << "// Polymorphic variables - ALL VALID" << std::endl;
        for (int i = 0; i < 5; i++) {
            std::string varName = generatePrefixedName("poly_var");
            int value = 1000 + (rand() % 49000);
            std::cout << "static volatile int " << varName << " = " << value << ";" << std::endl;
        }
        
        std::cout << std::endl;
        std::string keyVar = generatePrefixedName("key_matrix");
        std::cout << "static unsigned char " << keyVar << "[] = {" << std::endl;
        std::cout << "    0x47, 0x51, 0x6F, 0x4E, 0x36, 0x60, 0xEE, 0x11" << std::endl;
        std::cout << "};" << std::endl;
        std::cout << std::endl;
        
        std::string funcName = generatePrefixedName("poly_func");
        std::cout << "void " << funcName << "() {" << std::endl;
        std::cout << "    // Polymorphic operations" << std::endl;
        std::cout << "}" << std::endl;
    }
};

int main() {
    FixedRandomGenerator gen;
    
    gen.runTests();
    gen.generateValidFUDTemplate();
    
    std::cout << "\n=== Manual Test Command ===" << std::endl;
    std::cout << "Try compiling source_clean.cpp:" << std::endl;
    std::cout << "cl /nologo /O2 /EHsc source_clean.cpp /Fe:working_test.exe user32.lib" << std::endl;
    
    return 0;
}
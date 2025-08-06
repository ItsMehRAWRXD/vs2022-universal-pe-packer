#include <iostream>
#include <string>
#include <random>
#include <chrono>

// Fixed Variable Name Generator for FUD Code
class ValidVariableGenerator {
private:
    std::random_device rd;
    std::mt19937 gen;
    
public:
    ValidVariableGenerator() : gen(rd()) {}
    
    // Generate valid C++ variable names (never start with digit)
    std::string generateValidVariableName(int length = 8) {
        // First character must be letter or underscore
        const std::string firstChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
        // Subsequent characters can include digits
        const std::string otherChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
        
        std::uniform_int_distribution<> firstDis(0, firstChars.length() - 1);
        std::uniform_int_distribution<> otherDis(0, otherChars.length() - 1);
        
        std::string result;
        
        // First character (no digits allowed)
        result += firstChars[firstDis(gen)];
        
        // Remaining characters (digits allowed)
        for (int i = 1; i < length; ++i) {
            result += otherChars[otherDis(gen)];
        }
        
        return result;
    }
    
    // Generate function names with specific prefixes
    std::string generateFunctionName(const std::string& prefix = "func") {
        return prefix + "_" + generateValidVariableName(8);
    }
    
    // Generate variable names with type hints
    std::string generateVariableName(const std::string& type = "var") {
        return type + "_" + generateValidVariableName(6);
    }
};

// Test the generator
int main() {
    ValidVariableGenerator gen;
    
    std::cout << "=== Valid C++ Variable Names ===" << std::endl;
    
    // Test variable names
    std::cout << "\nVariable Names:" << std::endl;
    for (int i = 0; i < 10; i++) {
        std::string varName = gen.generateValidVariableName();
        std::cout << "static volatile int " << varName << " = 12345;" << std::endl;
    }
    
    // Test function names
    std::cout << "\nFunction Names:" << std::endl;
    for (int i = 0; i < 5; i++) {
        std::string funcName = gen.generateFunctionName("poly");
        std::cout << "void " << funcName << "() { /* code */ }" << std::endl;
    }
    
    // Test with type prefixes
    std::cout << "\nTyped Variable Names:" << std::endl;
    std::cout << "unsigned char " << gen.generateVariableName("key") << "[] = {0x01, 0x02};" << std::endl;
    std::cout << "unsigned char " << gen.generateVariableName("data") << "[] = {0xAA, 0xBB};" << std::endl;
    std::cout << "unsigned char " << gen.generateVariableName("nonce") << "[] = {0xFF, 0xEE};" << std::endl;
    
    std::cout << "\n=== Fixed Source Code Example ===" << std::endl;
    
    // Generate a corrected version of the problematic source
    std::cout << "#include <windows.h>" << std::endl;
    std::cout << "#include <stdio.h>" << std::endl;
    std::cout << "#include <stdlib.h>" << std::endl;
    std::cout << "#include <string.h>" << std::endl;
    std::cout << std::endl;
    
    std::cout << "// Advanced polymorphic variables - unique per generation" << std::endl;
    for (int i = 0; i < 5; i++) {
        std::string varName = gen.generateValidVariableName(12);
        int value = 1000 + (rand() % 49000);
        std::cout << "static volatile int " << varName << " = " << value << ";" << std::endl;
    }
    
    std::cout << std::endl;
    std::cout << "// Encryption key matrix" << std::endl;
    std::string keyVar = gen.generateVariableName("key_matrix");
    std::cout << "static unsigned char " << keyVar << "[] = {" << std::endl;
    std::cout << "    0x47, 0x51, 0x6F, 0x4E, 0x36, 0x60, 0xEE, 0x11," << std::endl;
    std::cout << "    0x71, 0x65, 0xFF, 0xBD, 0x0E, 0xEC, 0x90, 0xDD" << std::endl;
    std::cout << "};" << std::endl;
    
    return 0;
}
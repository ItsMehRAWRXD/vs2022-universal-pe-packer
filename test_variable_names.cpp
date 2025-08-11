#include <iostream>
#include <string>
#include <random>
#include <cctype>

class FixedRandomEngine {
private:
    std::random_device rd;
    std::mt19937 gen;
    
public:
    FixedRandomEngine() : gen(rd()) {}
    
    std::string generateRandomName(int length = 8) {
        // First character MUST be a letter (no digits allowed)
        const std::string firstChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
        // Subsequent characters can include digits
        const std::string otherChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
        
        std::uniform_int_distribution<> firstDis(0, static_cast<int>(firstChars.length() - 1));
        std::uniform_int_distribution<> otherDis(0, static_cast<int>(otherChars.length() - 1));
        
        std::string result;
        
        // First character (no digits)
        if (length > 0) {
            result += firstChars[firstDis(gen)];
        }
        
        // Remaining characters (can include digits)
        for (int i = 1; i < length; ++i) {
            result += otherChars[otherDis(gen)];
        }
        
        return result;
    }
};

bool isValidCppIdentifier(const std::string& name) {
    if (name.empty()) return false;
    
    // First character must be letter or underscore
    if (!std::isalpha(name[0]) && name[0] != '_') {
        return false;
    }
    
    // Remaining characters must be alphanumeric or underscore
    for (size_t i = 1; i < name.size(); ++i) {
        if (!std::isalnum(name[i]) && name[i] != '_') {
            return false;
        }
    }
    
    return true;
}

int main() {
    FixedRandomEngine randomEngine;
    
    std::cout << "=== Testing Fixed Variable Name Generator ===" << std::endl;
    std::cout << "Generating 100 variable names to test validity..." << std::endl;
    
    int validCount = 0;
    int invalidCount = 0;
    
    for (int i = 0; i < 100; ++i) {
        std::string name = randomEngine.generateRandomName(8);
        bool valid = isValidCppIdentifier(name);
        
        if (valid) {
            validCount++;
            if (i < 20) {  // Show first 20 examples
                std::cout << "✅ " << name << std::endl;
            }
        } else {
            invalidCount++;
            std::cout << "❌ INVALID: " << name << " (";
            if (std::isdigit(name[0])) {
                std::cout << "starts with digit";
            } else {
                std::cout << "contains invalid chars";
            }
            std::cout << ")" << std::endl;
        }
    }
    
    std::cout << "\n=== RESULTS ===" << std::endl;
    std::cout << "✅ Valid names: " << validCount << "/100" << std::endl;
    std::cout << "❌ Invalid names: " << invalidCount << "/100" << std::endl;
    
    if (invalidCount == 0) {
        std::cout << "🎉 SUCCESS: All generated names are valid C++ identifiers!" << std::endl;
    } else {
        std::cout << "⚠️  FAILURE: " << invalidCount << " invalid names found!" << std::endl;
    }
    
    // Test edge cases
    std::cout << "\n=== Testing Edge Cases ===" << std::endl;
    
    std::string shortName = randomEngine.generateRandomName(3);
    std::string longName = randomEngine.generateRandomName(15);
    
    std::cout << "Short name (3 chars): " << shortName << " - " 
              << (isValidCppIdentifier(shortName) ? "✅ Valid" : "❌ Invalid") << std::endl;
    std::cout << "Long name (15 chars): " << longName << " - " 
              << (isValidCppIdentifier(longName) ? "✅ Valid" : "❌ Invalid") << std::endl;
    
    return 0;
}
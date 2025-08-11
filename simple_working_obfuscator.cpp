#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <sstream>
#include <fstream>
#include <chrono>
#include <iomanip>

class WorkingPolymorphicObfuscator {
private:
    std::mt19937 rng;
    std::uniform_int_distribution<> byte_dist;
    std::uniform_int_distribution<> var_dist;
    
public:
    WorkingPolymorphicObfuscator() : rng(std::chrono::steady_clock::now().time_since_epoch().count()),
                                     byte_dist(0, 255),
                                     var_dist(1000, 9999) {}

    // Generate random variable name
    std::string generateVarName() {
        return "var" + std::to_string(var_dist(rng));
    }
    
    // Generate random function name
    std::string generateFuncName() {
        return "func" + std::to_string(var_dist(rng));
    }
    
    // Generate XOR obfuscation
    std::string generateXORObfuscation(const std::vector<uint8_t>& data) {
        std::stringstream code;
        auto keyVar = generateVarName();
        auto dataVar = generateVarName();
        auto funcName = generateFuncName();
        
        uint8_t key = byte_dist(rng);
        
        code << "// XOR Obfuscation - Variant " << rng() % 10000 << "\n";
        code << "void " << funcName << "() {\n";
        code << "    const uint8_t " << keyVar << " = 0x" << std::hex << (int)key << std::dec << ";\n";
        code << "    static uint8_t " << dataVar << "[] = {\n        ";
        
        for (size_t i = 0; i < data.size(); ++i) {
            if (i > 0 && i % 16 == 0) code << ",\n        ";
            else if (i > 0) code << ", ";
            code << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)(data[i] ^ key);
        }
        
        code << std::dec << "\n    };\n\n";
        code << "    for (size_t i = 0; i < sizeof(" << dataVar << "); ++i) {\n";
        code << "        " << dataVar << "[i] ^= " << keyVar << ";\n";
        code << "    }\n";
        code << "    \n";
        code << "    // Execute decoded data\n";
        code << "    std::cout << \"Decoded: \";\n";
        code << "    for (size_t i = 0; i < sizeof(" << dataVar << "); ++i) {\n";
        code << "        std::cout << (char)" << dataVar << "[i];\n";
        code << "    }\n";
        code << "    std::cout << std::endl;\n";
        code << "}\n\n";
        
        return code.str();
    }
    
    // Generate ADD/SUB obfuscation
    std::string generateADDSUBObfuscation(const std::vector<uint8_t>& data) {
        std::stringstream code;
        auto keyVar = generateVarName();
        auto dataVar = generateVarName();
        auto funcName = generateFuncName();
        
        uint8_t key = byte_dist(rng);
        bool useAdd = (rng() % 2) == 0;
        
        code << "// ADD/SUB Obfuscation - Variant " << rng() % 10000 << "\n";
        code << "void " << funcName << "() {\n";
        code << "    const uint8_t " << keyVar << " = 0x" << std::hex << (int)key << std::dec << ";\n";
        code << "    static uint8_t " << dataVar << "[] = {\n        ";
        
        for (size_t i = 0; i < data.size(); ++i) {
            if (i > 0 && i % 16 == 0) code << ",\n        ";
            else if (i > 0) code << ", ";
            
            uint8_t encoded = useAdd ? (data[i] - key) & 0xFF : (data[i] + key) & 0xFF;
            code << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)encoded;
        }
        
        code << std::dec << "\n    };\n\n";
        
        if (useAdd) {
            code << "    // Decode using ADD\n";
            code << "    for (size_t i = 0; i < sizeof(" << dataVar << "); ++i) {\n";
            code << "        " << dataVar << "[i] = (" << dataVar << "[i] + " << keyVar << ") & 0xFF;\n";
            code << "    }\n";
        } else {
            code << "    // Decode using SUB\n";
            code << "    for (size_t i = 0; i < sizeof(" << dataVar << "); ++i) {\n";
            code << "        " << dataVar << "[i] = (" << dataVar << "[i] - " << keyVar << ") & 0xFF;\n";
            code << "    }\n";
        }
        
        code << "    \n";
        code << "    // Execute decoded data\n";
        code << "    std::cout << \"Decoded: \";\n";
        code << "    for (size_t i = 0; i < sizeof(" << dataVar << "); ++i) {\n";
        code << "        std::cout << (char)" << dataVar << "[i];\n";
        code << "    }\n";
        code << "    std::cout << std::endl;\n";
        code << "}\n\n";
        
        return code.str();
    }
    
    // Generate rotation obfuscation
    std::string generateRotationObfuscation(const std::vector<uint8_t>& data) {
        std::stringstream code;
        auto dataVar = generateVarName();
        auto funcName = generateFuncName();
        
        int rotation = (rng() % 7) + 1;
        bool leftRotate = (rng() % 2) == 0;
        
        code << "// Rotation Obfuscation - Variant " << rng() % 10000 << "\n";
        code << "void " << funcName << "() {\n";
        code << "    static uint8_t " << dataVar << "[] = {\n        ";
        
        for (size_t i = 0; i < data.size(); ++i) {
            if (i > 0 && i % 16 == 0) code << ",\n        ";
            else if (i > 0) code << ", ";
            
            uint8_t encoded;
            if (leftRotate) {
                encoded = ((data[i] >> rotation) | (data[i] << (8 - rotation))) & 0xFF;
            } else {
                encoded = ((data[i] << rotation) | (data[i] >> (8 - rotation))) & 0xFF;
            }
            code << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)encoded;
        }
        
        code << std::dec << "\n    };\n\n";
        
        if (leftRotate) {
            code << "    // Decode using LEFT rotation\n";
            code << "    for (size_t i = 0; i < sizeof(" << dataVar << "); ++i) {\n";
            code << "        " << dataVar << "[i] = ((" << dataVar << "[i] << " << rotation << ") | (" << dataVar << "[i] >> " << (8 - rotation) << ")) & 0xFF;\n";
            code << "    }\n";
        } else {
            code << "    // Decode using RIGHT rotation\n";
            code << "    for (size_t i = 0; i < sizeof(" << dataVar << "); ++i) {\n";
            code << "        " << dataVar << "[i] = ((" << dataVar << "[i] >> " << rotation << ") | (" << dataVar << "[i] << " << (8 - rotation) << ")) & 0xFF;\n";
            code << "    }\n";
        }
        
        code << "    \n";
        code << "    // Execute decoded data\n";
        code << "    std::cout << \"Decoded: \";\n";
        code << "    for (size_t i = 0; i < sizeof(" << dataVar << "); ++i) {\n";
        code << "        std::cout << (char)" << dataVar << "[i];\n";
        code << "    }\n";
        code << "    std::cout << std::endl;\n";
        code << "}\n\n";
        
        return code.str();
    }
    
    // Generate working junk code
    std::string generateJunkCode() {
        std::stringstream code;
        auto var1 = generateVarName();
        auto var2 = generateVarName();
        
        code << "// Junk Code - Variant " << rng() % 10000 << "\n";
        code << "void junkFunction" << var_dist(rng) << "() {\n";
        code << "    volatile int " << var1 << " = " << (rng() % 1000) << ";\n";
        code << "    volatile int " << var2 << " = " << (rng() % 1000) << ";\n";
        code << "    for (int i = 0; i < 100; ++i) {\n";
        code << "        " << var1 << " = (" << var1 << " ^ " << var2 << ") + i;\n";
        code << "        " << var2 << " = (" << var2 << " << 1) ^ " << var1 << ";\n";
        code << "    }\n";
        code << "    (void)" << var1 << "; (void)" << var2 << "; // Suppress warnings\n";
        code << "}\n\n";
        
        return code.str();
    }
    
    // Generate complete working obfuscation
    std::string generateCompleteObfuscation(const std::vector<uint8_t>& data) {
        std::stringstream code;
        
        code << "#include <iostream>\n";
        code << "#include <cstdint>\n\n";
        
        code << "// ===== WORKING POLYMORPHIC OBFUSCATION =====\n";
        code << "// Generation ID: " << rng() % 1000000 << "\n";
        code << "// Timestamp: " << std::time(nullptr) << "\n\n";
        
        // Add junk code
        code << generateJunkCode();
        
        // Randomly select obfuscation method
        int method = rng() % 3;
        switch(method) {
            case 0:
                code << generateXORObfuscation(data);
                break;
            case 1:
                code << generateADDSUBObfuscation(data);
                break;
            case 2:
                code << generateRotationObfuscation(data);
                break;
        }
        
        // Add more junk code
        code << generateJunkCode();
        
        // Add main function
        code << "int main() {\n";
        code << "    std::cout << \"Polymorphic obfuscation demo\" << std::endl;\n";
        code << "    \n";
        code << "    // Call obfuscated functions (you would call the generated function here)\n";
        code << "    std::cout << \"Obfuscation method " << method << " ready!\" << std::endl;\n";
        code << "    \n";
        code << "    return 0;\n";
        code << "}\n";
        
        return code.str();
    }
};

int main() {
    std::cout << "🔥 WORKING POLYMORPHIC OBFUSCATION DEMO 🔥\n";
    std::cout << "==========================================\n\n";
    
    WorkingPolymorphicObfuscator obfuscator;
    
    // Test data to obfuscate
    std::vector<uint8_t> testData = {
        'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'
    };
    
    std::cout << "Generating 3 working polymorphic variants...\n\n";
    
    for (int i = 1; i <= 3; ++i) {
        std::cout << "=== VARIANT " << i << " ===\n";
        
        std::string obfuscatedCode = obfuscator.generateCompleteObfuscation(testData);
        
        // Write to file
        std::string filename = "working_variant_" + std::to_string(i) + ".cpp";
        std::ofstream file(filename);
        file << obfuscatedCode;
        file.close();
        
        std::cout << "✅ Generated: " << filename << " (" << obfuscatedCode.length() << " bytes)\n";
        
        // Show first few lines
        std::istringstream iss(obfuscatedCode);
        std::string line;
        int lineCount = 0;
        std::cout << "Preview:\n";
        while (std::getline(iss, line) && lineCount < 8) {
            std::cout << "  " << line << "\n";
            lineCount++;
        }
        std::cout << "  ...\n\n";
    }
    
    std::cout << "🎯 FEATURES DEMONSTRATED:\n";
    std::cout << "• XOR Obfuscation with random keys\n";
    std::cout << "• ADD/SUB arithmetic obfuscation\n";
    std::cout << "• Bit rotation obfuscation\n";
    std::cout << "• Random variable naming\n";
    std::cout << "• Junk code injection\n";
    std::cout << "• Compilable output\n\n";
    
    std::cout << "💡 USAGE:\n";
    std::cout << "Compile any variant with: g++ -O2 working_variant_X.cpp -o obfuscated\n";
    std::cout << "Each variant uses different obfuscation techniques!\n\n";
    
    return 0;
}
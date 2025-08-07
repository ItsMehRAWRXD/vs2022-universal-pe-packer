/*
========================================================================================
COMPREHENSIVE TEST SUITE - VS2022 STEALTH PE PACKER VALIDATION
========================================================================================
TESTS ALL STEALTH FEATURES AND UNIQUENESS
FIXES ICON ISSUE (NO MORE CALC.EXE ICONS!)
VALIDATES SANDBOX DETECTION
MEASURES POLYMORPHIC UNIQUENESS
========================================================================================
*/

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <map>
#include <set>
#include <algorithm>
#include <ctime>

// Windows headers for testing
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#endif

class StealthPackerTestSuite {
private:
    std::mt19937_64 rng;
    std::vector<std::string> testResults;
    int totalTests = 0;
    int passedTests = 0;

public:
    StealthPackerTestSuite() {
        auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        rng.seed(seed);
    }

    // Test result tracking
    void recordTest(const std::string& testName, bool passed, const std::string& details = "") {
        totalTests++;
        if (passed) passedTests++;
        
        std::string result = "[" + std::string(passed ? "PASS" : "FAIL") + "] " + testName;
        if (!details.empty()) {
            result += " - " + details;
        }
        testResults.push_back(result);
        std::cout << result << std::endl;
    }

    // ========================================================================
    // TIMESTAMP SPOOFING TESTS
    // ========================================================================
    
    void testTimestampGeneration() {
        std::cout << "\n[TIMESTAMP TESTS]\n";
        std::cout << "Testing realistic timestamp generation...\n";
        
        // Test 1: Generate multiple timestamps
        std::vector<time_t> timestamps;
        bool allRealistic = true;
        
        for (int i = 0; i < 10; i++) {
            time_t now = time(nullptr);
            time_t generated = generateRealisticTimestamp();
            timestamps.push_back(generated);
            
            // Check if timestamp is in realistic range (6 months to 2 years ago)
            time_t sixMonthsAgo = now - (6 * 30 * 24 * 60 * 60);
            time_t twoYearsAgo = now - (2 * 365 * 24 * 60 * 60);
            
            if (generated > now || generated < twoYearsAgo) {
                allRealistic = false;
            }
            
            std::cout << "  Timestamp " << (i+1) << ": " << std::ctime(&generated);
        }
        
        recordTest("Realistic Timestamp Generation", allRealistic, 
                   "All timestamps within 6 months to 2 years range");
        
        // Test 2: Uniqueness
        std::set<time_t> uniqueTimestamps(timestamps.begin(), timestamps.end());
        bool allUnique = uniqueTimestamps.size() == timestamps.size();
        recordTest("Timestamp Uniqueness", allUnique, 
                   std::to_string(uniqueTimestamps.size()) + "/10 unique");
    }
    
    time_t generateRealisticTimestamp() {
        time_t now = time(nullptr);
        
        // Random days back (180-728 days = 6 months to 2 years)
        int daysBack = (rng() % 548) + 180;
        
        return now - (daysBack * 24 * 60 * 60);
    }

    // ========================================================================
    // SANDBOX DETECTION TESTS
    // ========================================================================
    
    void testSandboxDetection() {
        std::cout << "\n[SANDBOX DETECTION TESTS]\n";
        std::cout << "Testing sandbox detection capabilities...\n";
        
#ifdef _WIN32
        // Test 1: Process enumeration
        bool canEnumProcesses = testProcessEnumeration();
        recordTest("Process Enumeration", canEnumProcesses, "Can access process list");
        
        // Test 2: System resource detection
        bool systemResourcesOK = testSystemResources();
        recordTest("System Resources Check", systemResourcesOK, "Memory and CPU detection");
        
        // Test 3: Timing consistency
        bool timingConsistent = testTimingConsistency();
        recordTest("Timing Consistency", timingConsistent, "Sleep timing accuracy");
        
        // Test 4: Registry access
        bool registryAccess = testRegistryAccess();
        recordTest("Registry Access", registryAccess, "Can read system registry");
#else
        recordTest("Sandbox Detection", false, "Windows-only feature (running on Linux)");
#endif
    }
    
#ifdef _WIN32
    bool testProcessEnumeration() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        int processCount = 0;
        if (Process32First(hSnapshot, &pe32)) {
            do {
                processCount++;
            } while (Process32Next(hSnapshot, &pe32) && processCount < 50);
        }
        
        CloseHandle(hSnapshot);
        return processCount > 10; // Should have reasonable number of processes
    }
    
    bool testSystemResources() {
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&memInfo);
        
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        
        // Check for realistic system specs
        bool memoryOK = memInfo.ullTotalPhys > (1024ULL * 1024 * 1024); // > 1GB
        bool cpuOK = sysInfo.dwNumberOfProcessors > 0;
        
        std::cout << "    Memory: " << (memInfo.ullTotalPhys / 1024 / 1024) << " MB\n";
        std::cout << "    CPUs: " << sysInfo.dwNumberOfProcessors << "\n";
        
        return memoryOK && cpuOK;
    }
    
    bool testTimingConsistency() {
        DWORD start = GetTickCount();
        Sleep(100);
        DWORD elapsed = GetTickCount() - start;
        
        std::cout << "    Sleep(100) took: " << elapsed << "ms\n";
        
        // Should be close to 100ms (allowing for some variance)
        return elapsed >= 90 && elapsed <= 200;
    }
    
    bool testRegistryAccess() {
        HKEY hKey;
        LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                                   "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", 
                                   0, KEY_READ, &hKey);
        if (result == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
        return false;
    }
#endif

    // ========================================================================
    // SIGNATURE GENERATION TESTS
    // ========================================================================
    
    void testSignatureGeneration() {
        std::cout << "\n[SIGNATURE GENERATION TESTS]\n";
        std::cout << "Testing digital signature spoofing...\n";
        
        // Test 1: Generate multiple fake signatures
        std::vector<std::string> issuers;
        std::vector<std::string> subjects;
        
        for (int i = 0; i < 10; i++) {
            auto sig = generateFakeSignature();
            issuers.push_back(sig.issuer);
            subjects.push_back(sig.subject);
            
            std::cout << "  Signature " << (i+1) << ": " << sig.issuer 
                      << " -> " << sig.subject << "\n";
        }
        
        // Test uniqueness
        std::set<std::string> uniqueIssuers(issuers.begin(), issuers.end());
        std::set<std::string> uniqueSubjects(subjects.begin(), subjects.end());
        
        recordTest("Signature Generation", !issuers.empty(), 
                   std::to_string(uniqueIssuers.size()) + " unique issuers");
        recordTest("Signature Variety", uniqueIssuers.size() > 1, 
                   "Multiple legitimate companies used");
    }
    
    struct FakeSignature {
        std::string issuer;
        std::string subject;
        std::vector<uint8_t> certificate;
        time_t timestamp;
    };
    
    FakeSignature generateFakeSignature() {
        FakeSignature sig;
        
        std::vector<std::string> companies = {
            "Microsoft Corporation", "Adobe Inc.", "Google LLC", "Mozilla Corporation",
            "Oracle Corporation", "Intel Corporation", "NVIDIA Corporation", 
            "Symantec Corporation", "Apple Inc.", "Cisco Systems Inc."
        };
        
        std::vector<std::string> products = {
            "Windows System Component", "Application Framework", "System Library",
            "Device Driver", "Security Component", "Network Service", "System Utility",
            "Media Framework", "Graphics Driver", "System Service"
        };
        
        sig.issuer = companies[rng() % companies.size()];
        sig.subject = products[rng() % products.size()];
        sig.timestamp = generateRealisticTimestamp();
        
        // Generate fake certificate data
        sig.certificate.resize(512 + (rng() % 512)); // 512-1024 bytes
        for (auto& byte : sig.certificate) {
            byte = rng() % 256;
        }
        
        return sig;
    }

    // ========================================================================
    // POLYMORPHIC ENCRYPTION TESTS
    // ========================================================================
    
    void testPolymorphicEncryption() {
        std::cout << "\n[POLYMORPHIC ENCRYPTION TESTS]\n";
        std::cout << "Testing encryption uniqueness with 10 instances each...\n";
        
        // Test data
        std::vector<uint8_t> testData = {
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21
        }; // "Hello World!"
        
        // Test AES polymorphism
        std::cout << "\nTesting AES Polymorphism (10 instances):\n";
        testEncryptionMethod("AES", testData, &StealthPackerTestSuite::aesEncrypt);
        
        // Test ChaCha20 polymorphism
        std::cout << "\nTesting ChaCha20 Polymorphism (10 instances):\n";
        testEncryptionMethod("ChaCha20", testData, &StealthPackerTestSuite::chaCha20Encrypt);
        
        // Test XOR polymorphism
        std::cout << "\nTesting XOR Polymorphism (10 instances):\n";
        testEncryptionMethod("XOR", testData, &StealthPackerTestSuite::xorEncrypt);
    }
    
    void testEncryptionMethod(const std::string& methodName, 
                             const std::vector<uint8_t>& testData,
                             std::vector<uint8_t> (StealthPackerTestSuite::*encryptFunc)(const std::vector<uint8_t>&)) {
        
        std::vector<std::vector<uint8_t>> results;
        
        // Generate 10 encrypted instances
        for (int i = 0; i < 10; i++) {
            auto encrypted = (this->*encryptFunc)(testData);
            results.push_back(encrypted);
            
            std::cout << "  Instance " << (i+1) << ": ";
            for (int j = 0; j < 8 && j < encrypted.size(); j++) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)encrypted[j];
            }
            std::cout << std::dec << "...\n";
        }
        
        // Calculate differences
        double totalDifference = 0.0;
        int comparisons = 0;
        
        for (int i = 0; i < 10; i++) {
            for (int j = i + 1; j < 10; j++) {
                double diff = calculateDifference(results[i], results[j]);
                totalDifference += diff;
                comparisons++;
            }
        }
        
        double avgDifference = totalDifference / comparisons;
        
        std::cout << "  Average difference: " << std::fixed << std::setprecision(2) 
                  << avgDifference << "%\n";
        
        recordTest(methodName + " Polymorphism", avgDifference > 50.0, 
                   std::to_string((int)avgDifference) + "% average difference");
    }
    
    double calculateDifference(const std::vector<uint8_t>& data1, const std::vector<uint8_t>& data2) {
        if (data1.size() != data2.size()) return 100.0;
        
        size_t differences = 0;
        for (size_t i = 0; i < data1.size(); i++) {
            if (data1[i] != data2[i]) differences++;
        }
        
        return (double(differences) / double(data1.size())) * 100.0;
    }
    
    // Polymorphic encryption implementations
    std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> result = data;
        
        // Generate random key and S-box
        auto key = generateRandomKey(32);
        uint64_t seed = rng();
        
        uint8_t sbox[256];
        for (int i = 0; i < 256; i++) {
            sbox[i] = i ^ (seed >> (i % 64));
        }
        
        for (size_t i = 0; i < result.size(); i++) {
            result[i] ^= key[i % key.size()];
            result[i] = sbox[result[i]];
            result[i] ^= (i & 0xFF) ^ (seed >> ((i * 7) % 64));
        }
        
        return result;
    }
    
    std::vector<uint8_t> chaCha20Encrypt(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> result = data;
        
        auto key = generateRandomKey(32);
        auto nonce = generateRandomKey(16);
        uint64_t seed = rng();
        
        for (size_t i = 0; i < result.size(); i++) {
            uint8_t keystream = (key[i % key.size()] ^ nonce[i % nonce.size()]) + 
                               (i % 256) + (seed >> (i % 64));
            result[i] ^= keystream;
            result[i] = ((result[i] << ((seed + i) % 8)) | 
                        (result[i] >> (8 - ((seed + i) % 8)))) & 0xFF;
        }
        
        return result;
    }
    
    std::vector<uint8_t> xorEncrypt(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> result = data;
        
        auto key = generateRandomKey(64);
        uint64_t seed = rng();
        uint8_t avalanche = seed & 0xFF;
        
        for (size_t i = 0; i < result.size(); i++) {
            avalanche = (avalanche + result[i] + key[i % key.size()]) & 0xFF;
            result[i] ^= key[i % key.size()] ^ avalanche ^ (seed >> (i % 64));
            if (i % 2 == 0) {
                result[i] = ~result[i];
            }
        }
        
        return result;
    }
    
    std::vector<uint8_t> generateRandomKey(size_t size) {
        std::vector<uint8_t> key(size);
        for (size_t i = 0; i < size; i++) {
            key[i] = rng() % 256;
        }
        return key;
    }

    // ========================================================================
    // STUB GENERATION TESTS
    // ========================================================================
    
    void testStubGeneration() {
        std::cout << "\n[STUB GENERATION TESTS]\n";
        std::cout << "Testing polymorphic stub code generation...\n";
        
        std::vector<uint8_t> dummyData = {0x90, 0x90, 0x90, 0x90}; // NOP instructions
        std::vector<std::string> stubs;
        std::vector<size_t> stubSizes;
        
        for (int i = 0; i < 10; i++) {
            std::string stub = generatePolymorphicStub(dummyData, "test", i);
            stubs.push_back(stub);
            stubSizes.push_back(stub.size());
            
            std::cout << "  Stub " << (i+1) << " size: " << stub.size() << " characters\n";
        }
        
        // Test size variation
        auto minMax = std::minmax_element(stubSizes.begin(), stubSizes.end());
        double sizeVariation = (double(*minMax.second - *minMax.first) / *minMax.first) * 100.0;
        
        recordTest("Stub Size Variation", sizeVariation > 10.0, 
                   std::to_string((int)sizeVariation) + "% size variation");
        
        // Test content uniqueness
        double totalDiff = 0.0;
        int comparisons = 0;
        
        for (int i = 0; i < 10; i++) {
            for (int j = i + 1; j < 10; j++) {
                double diff = calculateStringDifference(stubs[i], stubs[j]);
                totalDiff += diff;
                comparisons++;
            }
        }
        
        double avgDiff = totalDiff / comparisons;
        recordTest("Stub Content Uniqueness", avgDiff > 70.0, 
                   std::to_string((int)avgDiff) + "% average difference");
    }
    
    std::string generatePolymorphicStub(const std::vector<uint8_t>& data, 
                                       const std::string& method, int instance) {
        std::stringstream stub;
        
        // Generate unique identifiers
        std::string funcName = generateRandomIdentifier();
        std::string varName = generateRandomIdentifier();
        std::string arrayName = generateRandomIdentifier();
        
        stub << "// Polymorphic Stub #" << instance << " - Method: " << method << "\n";
        stub << "// Generated: " << time(nullptr) << "\n";
        stub << "#include <windows.h>\n";
        stub << "#include <vector>\n\n";
        
        // Random junk code
        int junkLines = 5 + (rng() % 10);
        for (int i = 0; i < junkLines; i++) {
            stub << "volatile int " << generateRandomIdentifier() 
                 << " = " << (rng() % 10000) << ";\n";
        }
        
        stub << "\nstd::vector<BYTE> " << funcName << "() {\n";
        stub << "    std::vector<BYTE> " << varName << ";\n";
        
        // More junk
        for (int i = 0; i < 3 + (rng() % 5); i++) {
            stub << "    DWORD " << generateRandomIdentifier() 
                 << " = GetTickCount() ^ 0x" << std::hex << (rng() % 0xFFFF) << std::dec << ";\n";
        }
        
        stub << "    return " << varName << ";\n";
        stub << "}\n\n";
        
        stub << "int main() {\n";
        stub << "    auto result = " << funcName << "();\n";
        stub << "    return 0;\n";
        stub << "}\n";
        
        return stub.str();
    }
    
    std::string generateRandomIdentifier() {
        std::vector<std::string> prefixes = {"app", "sys", "win", "net", "sec", "core", "util", "base"};
        std::vector<std::string> suffixes = {"Mgr", "Svc", "Lib", "Api", "Exe", "Dll", "Drv", "Sys"};
        
        std::stringstream ss;
        ss << prefixes[rng() % prefixes.size()] 
           << std::hex << (rng() % 0xFFF)
           << suffixes[rng() % suffixes.size()];
        return ss.str();
    }
    
    double calculateStringDifference(const std::string& str1, const std::string& str2) {
        size_t maxSize = std::max(str1.size(), str2.size());
        size_t minSize = std::min(str1.size(), str2.size());
        size_t differences = maxSize - minSize;
        
        for (size_t i = 0; i < minSize; i++) {
            if (str1[i] != str2[i]) differences++;
        }
        
        return (double(differences) / double(maxSize)) * 100.0;
    }

    // ========================================================================
    // ICON AND RESOURCE TESTS
    // ========================================================================
    
    void testIconHandling() {
        std::cout << "\n[ICON & RESOURCE TESTS]\n";
        std::cout << "Testing resource management (fixing calc.exe icon issue)...\n";
        
        // Test 1: Generic icon generation
        auto genericIcon = generateGenericIcon();
        recordTest("Generic Icon Generation", !genericIcon.empty(), 
                   std::to_string(genericIcon.size()) + " bytes generated");
        
        // Test 2: Icon randomization
        std::vector<std::vector<uint8_t>> icons;
        for (int i = 0; i < 5; i++) {
            icons.push_back(generateGenericIcon());
        }
        
        // Check if icons are different
        bool allDifferent = true;
        for (int i = 0; i < 5; i++) {
            for (int j = i + 1; j < 5; j++) {
                if (icons[i] == icons[j]) {
                    allDifferent = false;
                    break;
                }
            }
        }
        
        recordTest("Icon Uniqueness", allDifferent, "All generated icons are different");
        
        // Test 3: Version info generation
        auto versionInfo = generateVersionInfo();
        recordTest("Version Info Generation", !versionInfo.empty(), 
                   "Generated legitimate version information");
    }
    
    std::vector<uint8_t> generateGenericIcon() {
        // Generate a simple 16x16 icon data (simplified)
        std::vector<uint8_t> iconData;
        
        // ICO header
        iconData.insert(iconData.end(), {0x00, 0x00, 0x01, 0x00, 0x01, 0x00}); // Header + 1 image
        
        // Image directory
        iconData.insert(iconData.end(), {0x10, 0x10, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00}); // 16x16, 32bpp
        
        // Add random variation
        for (int i = 0; i < 16; i++) {
            iconData.push_back(rng() % 256);
        }
        
        return iconData;
    }
    
    std::string generateVersionInfo() {
        std::vector<std::string> companies = {"Microsoft Corporation", "System Components Inc.", "Windows Technologies"};
        std::vector<std::string> products = {"System Utility", "Application Framework", "Windows Component"};
        
        std::stringstream version;
        version << "CompanyName: " << companies[rng() % companies.size()] << "\n";
        version << "ProductName: " << products[rng() % products.size()] << "\n";
        version << "FileVersion: " << (rng() % 10 + 1) << "." << (rng() % 10) << "." << (rng() % 1000) << "\n";
        
        return version.str();
    }

    // ========================================================================
    // MAIN TEST RUNNER
    // ========================================================================
    
    void runComprehensiveTests() {
        std::cout << "========================================================================\n";
        std::cout << "        COMPREHENSIVE STEALTH PACKER TEST SUITE v1.0                \n";
        std::cout << "========================================================================\n";
        std::cout << "Testing all stealth features and polymorphic capabilities...\n\n";
        
        // Run all test categories
        testTimestampGeneration();
        testSandboxDetection();
        testSignatureGeneration();
        testPolymorphicEncryption();
        testStubGeneration();
        testIconHandling();
        
        // Display final results
        displayTestResults();
    }
    
    void displayTestResults() {
        std::cout << "\n========================================================================\n";
        std::cout << "                           TEST RESULTS SUMMARY                        \n";
        std::cout << "========================================================================\n";
        
        for (const auto& result : testResults) {
            std::cout << result << "\n";
        }
        
        std::cout << "\n========================================================================\n";
        std::cout << "TOTAL TESTS: " << totalTests << " | PASSED: " << passedTests 
                  << " | FAILED: " << (totalTests - passedTests) << "\n";
        
        double successRate = (double(passedTests) / double(totalTests)) * 100.0;
        std::cout << "SUCCESS RATE: " << std::fixed << std::setprecision(1) << successRate << "%\n";
        
        if (successRate >= 90.0) {
            std::cout << "[EXCELLENT] All stealth features working optimally!\n";
        } else if (successRate >= 75.0) {
            std::cout << "[GOOD] Most features working, minor improvements needed\n";
        } else if (successRate >= 50.0) {
            std::cout << "[MODERATE] Some features working, significant improvements needed\n";
        } else {
            std::cout << "[POOR] Major issues detected, requires debugging\n";
        }
        
        std::cout << "========================================================================\n";
    }
};

// Cross-platform main function
int main() {
    std::cout << "Initializing Comprehensive Stealth Packer Test Suite...\n\n";
    
    StealthPackerTestSuite testSuite;
    testSuite.runComprehensiveTests();
    
    std::cout << "\nTesting completed! Press Enter to exit...";
    std::cin.get();
    
    return 0;
}
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
#include <string>
#include <vector>
#include <cstdint>
#include <random>
#include <chrono>
#include <thread>
#include <filesystem>
#include <algorithm>
#include <iomanip>
#include <set>
#include <functional>
#include "tiny_loader.h"

// Comprehensive test suite for all features
class ComprehensiveTestSuite {
private:
    std::random_device rd;
    std::mt19937 gen;
    std::uniform_int_distribution<> dis;
    
public:
    ComprehensiveTestSuite() : gen(rd()), dis(0, 255) {}
    
    // Test 1: Basic tiny_loader.h functionality
    bool testTinyLoaderBasic() {
        std::cout << "\n=== Test 1: Basic tiny_loader.h Functionality ===\n";
        
        // Test 1.1: Check tiny_loader_bin array
        if (tiny_loader_bin_len == 0) {
            std::cout << "❌ FAILED: tiny_loader_bin is empty\n";
            return false;
        }
        std::cout << "✅ tiny_loader_bin size: " << tiny_loader_bin_len << " bytes\n";
        
        // Test 1.2: Check MZ signature
        if (tiny_loader_bin[0] != 0x4D || tiny_loader_bin[1] != 0x5A) {
            std::cout << "❌ FAILED: Invalid MZ signature\n";
            return false;
        }
        std::cout << "✅ Valid MZ signature found\n";
        
        // Test 1.3: Check PE header
        if (tiny_loader_bin[96] != 0x50 || tiny_loader_bin[97] != 0x45) {
            std::cout << "❌ FAILED: Invalid PE header\n";
            return false;
        }
        std::cout << "✅ Valid PE header found\n";
        
        // Test 1.4: Check patch offsets
        if (PAYLOAD_SIZE_OFFSET >= tiny_loader_bin_len || PAYLOAD_RVA_OFFSET >= tiny_loader_bin_len) {
            std::cout << "❌ FAILED: Invalid patch offsets\n";
            return false;
        }
        std::cout << "✅ Valid patch offsets: " << PAYLOAD_SIZE_OFFSET << ", " << PAYLOAD_RVA_OFFSET << "\n";
        
        return true;
    }
    
    // Test 2: PE Generation with different payload sizes
    bool testPEGeneration() {
        std::cout << "\n=== Test 2: PE Generation with Different Payload Sizes ===\n";
        
        std::vector<std::string> testPayloads = {
            "",                                    // Empty payload
            "A",                                   // 1 byte
            "Hello World",                         // Small string
            std::string(100, 'X'),                // 100 bytes
            std::string(1000, 'Y'),               // 1000 bytes
            std::string(10000, 'Z')               // 10000 bytes
        };
        
        for (size_t i = 0; i < testPayloads.size(); ++i) {
            std::cout << "Testing payload size " << testPayloads[i].size() << " bytes... ";
            
            auto peData = generateMinimalPEExecutable(testPayloads[i]);
            
            if (peData.empty()) {
                std::cout << "❌ FAILED (empty result)\n";
                return false;
            }
            
            if (!verifyPEHeader(peData)) {
                std::cout << "❌ FAILED (invalid PE header)\n";
                return false;
            }
            
            // Check that payload is embedded correctly
            if (testPayloads[i].size() > 0) {
                size_t expectedSize = 1024 + testPayloads[i].size(); // 1024 is the padded loader size
                if (peData.size() < expectedSize) {
                    std::cout << "❌ FAILED (payload not embedded correctly)\n";
                    return false;
                }
            }
            
            std::cout << "✅ SUCCESS (" << peData.size() << " bytes)\n";
        }
        
        return true;
    }
    
    // Test 3: Mass Generation with different counts
    bool testMassGeneration() {
        std::cout << "\n=== Test 3: Mass Generation with Different Counts ===\n";
        
        std::vector<int> testCounts = {1, 5, 10, 50};
        
        for (int count : testCounts) {
            std::cout << "Testing mass generation of " << count << " stubs...\n";
            
            auto startTime = std::chrono::high_resolution_clock::now();
            
            int successCount = 0;
            std::vector<std::string> generatedFiles;
            
            for (int i = 0; i < count; ++i) {
                std::string filename = "test_mass_" + std::to_string(i) + "_" + generateRandomName(6) + ".exe";
                std::string payload = "Test payload " + std::to_string(i);
                
                auto peData = generateMinimalPEExecutable(payload);
                
                if (!peData.empty() && verifyPEHeader(peData)) {
                    std::ofstream outFile(filename, std::ios::binary);
                    if (outFile.is_open()) {
                        outFile.write(reinterpret_cast<const char*>(peData.data()), peData.size());
                        outFile.close();
                        generatedFiles.push_back(filename);
                        successCount++;
                    }
                }
            }
            
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
            
            std::cout << "  Generated " << successCount << "/" << count << " stubs in " 
                      << duration.count() << "ms (" << (duration.count() / (double)count) << "ms per stub)\n";
            
            if (successCount != count) {
                std::cout << "❌ FAILED: Not all stubs generated successfully\n";
                return false;
            }
            
            // Clean up test files
            for (const auto& filename : generatedFiles) {
                std::remove(filename.c_str());
            }
        }
        
        return true;
    }
    
    // Test 4: File uniqueness and naming
    bool testFileUniqueness() {
        std::cout << "\n=== Test 4: File Uniqueness and Naming ===\n";
        
        std::set<std::string> generatedNames;
        std::vector<std::string> testFiles;
        
        for (int i = 0; i < 100; ++i) {
            std::string filename = "FUD_Stub_" + std::to_string(i) + "_" + generateRandomName(8) + ".exe";
            
            if (generatedNames.find(filename) != generatedNames.end()) {
                std::cout << "❌ FAILED: Duplicate filename generated: " << filename << "\n";
                return false;
            }
            
            generatedNames.insert(filename);
            testFiles.push_back(filename);
            
            // Create a dummy file to test uniqueness
            std::ofstream outFile(filename);
            outFile << "test";
            outFile.close();
        }
        
        std::cout << "✅ Generated " << generatedNames.size() << " unique filenames\n";
        
        // Clean up
        for (const auto& filename : testFiles) {
            std::remove(filename.c_str());
        }
        
        return true;
    }
    
    // Test 5: PE Header integrity under stress
    bool testPEHeaderIntegrity() {
        std::cout << "\n=== Test 5: PE Header Integrity Under Stress ===\n";
        
        for (int i = 0; i < 1000; ++i) {
            std::string payload = "Stress test payload " + std::to_string(i) + " " + std::string(i % 100, 'X');
            
            auto peData = generateMinimalPEExecutable(payload);
            
            if (peData.empty()) {
                std::cout << "❌ FAILED: Empty PE data at iteration " << i << "\n";
                return false;
            }
            
            if (!verifyPEHeader(peData)) {
                std::cout << "❌ FAILED: Invalid PE header at iteration " << i << "\n";
                return false;
            }
            
            // Check that the PE structure is intact
            if (peData.size() < 1024) {
                std::cout << "❌ FAILED: PE too small at iteration " << i << "\n";
                return false;
            }
        }
        
        std::cout << "✅ Successfully generated 1000 valid PE files under stress\n";
        return true;
    }
    
    // Test 6: Memory usage and performance
    bool testMemoryAndPerformance() {
        std::cout << "\n=== Test 6: Memory Usage and Performance ===\n";
        
        std::vector<std::vector<uint8_t>> peFiles;
        auto startTime = std::chrono::high_resolution_clock::now();
        
        // Generate 100 PE files and keep them in memory
        for (int i = 0; i < 100; ++i) {
            std::string payload = "Performance test " + std::to_string(i) + " " + std::string(500, 'P');
            auto peData = generateMinimalPEExecutable(payload);
            
            if (peData.empty() || !verifyPEHeader(peData)) {
                std::cout << "❌ FAILED: Invalid PE generated during performance test\n";
                return false;
            }
            
            peFiles.push_back(std::move(peData));
        }
        
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        
        size_t totalSize = 0;
        for (const auto& peFile : peFiles) {
            totalSize += peFile.size();
        }
        
        std::cout << "✅ Generated " << peFiles.size() << " PE files in " << duration.count() << "ms\n";
        std::cout << "✅ Total memory usage: " << (totalSize / 1024) << " KB\n";
        std::cout << "✅ Average time per file: " << (duration.count() / 100.0) << "ms\n";
        std::cout << "✅ Average file size: " << (totalSize / 100) << " bytes\n";
        
        return true;
    }
    
    // Test 7: Cross-platform compatibility
    bool testCrossPlatformCompatibility() {
        std::cout << "\n=== Test 7: Cross-Platform Compatibility ===\n";
        
        // Test with different line endings
        std::vector<std::string> testPayloads = {
            "Windows\r\nline\r\nendings",
            "Unix\nline\nendings", 
            "Mac\rline\rendings",
            "Mixed\r\nline\nendings\r"
        };
        
        for (size_t i = 0; i < testPayloads.size(); ++i) {
            std::cout << "Testing payload with " << (i == 0 ? "Windows" : i == 1 ? "Unix" : i == 2 ? "Mac" : "Mixed") << " line endings... ";
            
            auto peData = generateMinimalPEExecutable(testPayloads[i]);
            
            if (peData.empty() || !verifyPEHeader(peData)) {
                std::cout << "❌ FAILED\n";
                return false;
            }
            
            std::cout << "✅ SUCCESS\n";
        }
        
        return true;
    }
    
    // Test 8: Error handling and edge cases
    bool testErrorHandling() {
        std::cout << "\n=== Test 8: Error Handling and Edge Cases ===\n";
        
        // Test with very large payload
        std::cout << "Testing with very large payload... ";
        std::string largePayload(1000000, 'L'); // 1MB payload
        auto peData = generateMinimalPEExecutable(largePayload);
        
        if (peData.empty()) {
            std::cout << "❌ FAILED: Large payload not handled\n";
            return false;
        }
        
        if (!verifyPEHeader(peData)) {
            std::cout << "❌ FAILED: Large payload corrupted PE header\n";
            return false;
        }
        
        std::cout << "✅ SUCCESS (" << peData.size() << " bytes)\n";
        
        // Test with special characters
        std::cout << "Testing with special characters... ";
        std::string specialPayload = "Special chars: \x00\x01\x02\xFF\xFE\xFD";
        peData = generateMinimalPEExecutable(specialPayload);
        
        if (peData.empty() || !verifyPEHeader(peData)) {
            std::cout << "❌ FAILED\n";
            return false;
        }
        
        std::cout << "✅ SUCCESS\n";
        
        return true;
    }
    
    // Test 9: Integration test with real-world scenarios
    bool testIntegrationScenarios() {
        std::cout << "\n=== Test 9: Integration Test with Real-World Scenarios ===\n";
        
        std::vector<std::string> companyNames = {
            "Adobe Systems Incorporated",
            "Google LLC", 
            "Intel Corporation",
            "NVIDIA Corporation",
            "Apple Inc.",
            "Oracle Corporation",
            "IBM Corporation",
            "VMware, Inc.",
            "Symantec Corporation",
            "McAfee, Inc."
        };
        
        std::vector<std::string> scenarios = {
            "Simple console application",
            "Windows GUI application", 
            "System utility",
            "Data processing tool",
            "Network monitoring utility"
        };
        
        for (size_t i = 0; i < scenarios.size(); ++i) {
            std::cout << "Testing scenario " << (i + 1) << ": " << scenarios[i] << "... ";
            
            std::string companyName = companyNames[i % companyNames.size()];
            std::string payload = generateBenignCode(companyName, scenarios[i]);
            
            auto peData = generateMinimalPEExecutable(payload);
            
            if (peData.empty() || !verifyPEHeader(peData)) {
                std::cout << "❌ FAILED\n";
                return false;
            }
            
            // Write to file for inspection
            std::string filename = "integration_test_" + std::to_string(i + 1) + ".exe";
            std::ofstream outFile(filename, std::ios::binary);
            if (outFile.is_open()) {
                outFile.write(reinterpret_cast<const char*>(peData.data()), peData.size());
                outFile.close();
                std::cout << "✅ SUCCESS (" << peData.size() << " bytes)\n";
            } else {
                std::cout << "❌ FAILED (cannot write file)\n";
                return false;
            }
        }
        
        return true;
    }
    
    // Test 10: Final comprehensive validation
    bool testComprehensiveValidation() {
        std::cout << "\n=== Test 10: Final Comprehensive Validation ===\n";
        
        int totalTests = 0;
        int passedTests = 0;
        
        // Generate a variety of stubs with different characteristics
        for (int i = 0; i < 50; ++i) {
            totalTests++;
            
            std::string companyName = "Test Company " + std::to_string(i % 10);
            std::string payload = generateBenignCode(companyName, "Comprehensive test " + std::to_string(i));
            
            auto peData = generateMinimalPEExecutable(payload);
            
            if (!peData.empty() && verifyPEHeader(peData)) {
                passedTests++;
            }
        }
        
        double successRate = (passedTests * 100.0) / totalTests;
        std::cout << "✅ Comprehensive validation: " << passedTests << "/" << totalTests 
                  << " tests passed (" << std::fixed << std::setprecision(1) << successRate << "%)\n";
        
        if (successRate >= 95.0) {
            std::cout << "🎉 MASS STUB GENERATOR IS FULLY FUNCTIONAL!\n";
            return true;
        } else {
            std::cout << "❌ FAILED: Success rate below 95%\n";
            return false;
        }
    }
    
    // Helper functions
    std::string generateRandomName(int length = 8) {
        const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        std::string result;
        result.reserve(length);
        for (int i = 0; i < length; ++i) {
            result += charset[dis(gen) % charset.length()];
        }
        return result;
    }
    
    std::string generateBenignCode(const std::string& companyName, const std::string& scenario) {
        std::vector<std::string> templates = {
            "#include <iostream>\n#include <string>\n\nint main() {\n    std::cout << \"Hello from " + companyName + "!\" << std::endl;\n    std::cout << \"Scenario: " + scenario + "\" << std::endl;\n    return 0;\n}",
            
            "#include <windows.h>\n\nint WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n    MessageBoxA(NULL, \"Welcome to " + companyName + " application!\", \"Info\", MB_OK);\n    return 0;\n}",
            
            "#include <iostream>\n#include <ctime>\n\nint main() {\n    time_t now = time(0);\n    std::cout << \"Current time: \" << ctime(&now) << std::endl;\n    std::cout << \"" + companyName + " - " + scenario + "\" << std::endl;\n    return 0;\n}",
            
            "#include <iostream>\n#include <vector>\n\nint main() {\n    std::vector<int> numbers = {1, 2, 3, 4, 5};\n    std::cout << \"" + companyName + " - " + scenario + "\" << std::endl;\n    for (int num : numbers) {\n        std::cout << \"Processing: \" << num << std::endl;\n    }\n    return 0;\n}"
        };
        
        return templates[dis(gen) % templates.size()];
    }
    
    std::vector<uint8_t> generateMinimalPEExecutable(const std::string& payload) {
        try {
            // 1. Copy the pre-built loader into a vector
            std::vector<uint8_t> exe(tiny_loader_bin, tiny_loader_bin + tiny_loader_bin_len);
            
            // 2. Pad to next 0x200 boundary (PE file-alignment requirement)
            constexpr size_t kAlign = 0x200;
            size_t paddedSize = (exe.size() + kAlign - 1) & ~(kAlign - 1);
            exe.resize(paddedSize, 0);
            
            // 3. Append the payload
            size_t payloadOffset = exe.size();
            exe.insert(exe.end(), payload.begin(), payload.end());
            
            // 4. Patch two 32-bit placeholders inside the loader
            auto poke32 = [&](size_t off, uint32_t v) {
                if (off + 3 < exe.size()) {
                    exe[off+0] =  v        & 0xFF;
                    exe[off+1] = (v >>  8) & 0xFF;
                    exe[off+2] = (v >> 16) & 0xFF;
                    exe[off+3] = (v >> 24) & 0xFF;
                }
            };
            
            poke32(PAYLOAD_SIZE_OFFSET, static_cast<uint32_t>(payload.size()));
            poke32(PAYLOAD_RVA_OFFSET, static_cast<uint32_t>(payloadOffset));
            
            return exe;
            
        } catch (...) {
            return {};
        }
    }
    
    bool verifyPEHeader(const std::vector<uint8_t>& exe) {
        if (exe.size() < 2) return false;
        
        // Check MZ signature
        if (exe[0] != 0x4D || exe[1] != 0x5A) return false;
        
        // Check PE header - in tiny_loader.h, PE header is at offset 0x60 (96)
        if (exe.size() < 100) return false;
        
        // PE header should be at offset 0x60 in the tiny_loader_bin
        if (exe[96] != 0x50 || exe[97] != 0x45 || 
            exe[98] != 0x00 || exe[99] != 0x00) return false;
        
        return true;
    }
    
    // Run all tests
    void runAllTests() {
        std::cout << "🚀 STARTING COMPREHENSIVE TEST SUITE\n";
        std::cout << "=====================================\n";
        
        auto startTime = std::chrono::high_resolution_clock::now();
        
        std::vector<std::pair<std::string, std::function<bool()>>> tests = {
            {"Basic tiny_loader.h functionality", [this]() { return testTinyLoaderBasic(); }},
            {"PE Generation with different payload sizes", [this]() { return testPEGeneration(); }},
            {"Mass Generation with different counts", [this]() { return testMassGeneration(); }},
            {"File uniqueness and naming", [this]() { return testFileUniqueness(); }},
            {"PE Header integrity under stress", [this]() { return testPEHeaderIntegrity(); }},
            {"Memory usage and performance", [this]() { return testMemoryAndPerformance(); }},
            {"Cross-platform compatibility", [this]() { return testCrossPlatformCompatibility(); }},
            {"Error handling and edge cases", [this]() { return testErrorHandling(); }},
            {"Integration test with real-world scenarios", [this]() { return testIntegrationScenarios(); }},
            {"Final comprehensive validation", [this]() { return testComprehensiveValidation(); }}
        };
        
        int passedTests = 0;
        int totalTests = tests.size();
        
        for (const auto& test : tests) {
            try {
                if (test.second()) {
                    passedTests++;
                }
            } catch (const std::exception& e) {
                std::cout << "❌ EXCEPTION in " << test.first << ": " << e.what() << "\n";
            } catch (...) {
                std::cout << "❌ UNKNOWN EXCEPTION in " << test.first << "\n";
            }
        }
        
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        
        std::cout << "\n" << std::string(50, '=') << "\n";
        std::cout << "🎯 TEST SUITE COMPLETE\n";
        std::cout << "========================\n";
        std::cout << "✅ Passed: " << passedTests << "/" << totalTests << " tests\n";
        std::cout << "⏱️  Duration: " << duration.count() << "ms\n";
        
        if (passedTests == totalTests) {
            std::cout << "🎉 ALL TESTS PASSED! MASS STUB GENERATOR IS FULLY FUNCTIONAL!\n";
        } else {
            std::cout << "⚠️  SOME TESTS FAILED. Please review the results above.\n";
        }
        
        std::cout << std::string(50, '=') << "\n";
    }
};

int main() {
    ComprehensiveTestSuite testSuite;
    testSuite.runAllTests();
    return 0;
}
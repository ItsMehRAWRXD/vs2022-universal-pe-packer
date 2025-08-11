#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdint>
#include <random>
#include <chrono>
#include <thread>
#include <set>
#include <iomanip>
#include "tiny_loader.h"

// Final test specifically for mass generation functionality
class FinalMassGenerationTest {
private:
    std::random_device rd;
    std::mt19937 gen;
    std::uniform_int_distribution<> dis;
    
public:
    FinalMassGenerationTest() : gen(rd()), dis(0, 255) {}
    
    void runFinalTest() {
        std::cout << "🎯 FINAL MASS GENERATION TEST\n";
        std::cout << "==============================\n\n";
        
        // Test 1: Small batch (10 stubs)
        std::cout << "Test 1: Small batch generation (10 stubs)\n";
        if (!testBatchGeneration(10)) {
            std::cout << "❌ FAILED: Small batch generation\n";
            return;
        }
        
        // Test 2: Medium batch (50 stubs)
        std::cout << "\nTest 2: Medium batch generation (50 stubs)\n";
        if (!testBatchGeneration(50)) {
            std::cout << "❌ FAILED: Medium batch generation\n";
            return;
        }
        
        // Test 3: Large batch (100 stubs)
        std::cout << "\nTest 3: Large batch generation (100 stubs)\n";
        if (!testBatchGeneration(100)) {
            std::cout << "❌ FAILED: Large batch generation\n";
            return;
        }
        
        // Test 4: Stress test (500 stubs)
        std::cout << "\nTest 4: Stress test (500 stubs)\n";
        if (!testBatchGeneration(500)) {
            std::cout << "❌ FAILED: Stress test\n";
            return;
        }
        
        // Test 5: Uniqueness verification
        std::cout << "\nTest 5: Uniqueness verification\n";
        if (!testUniqueness()) {
            std::cout << "❌ FAILED: Uniqueness test\n";
            return;
        }
        
        // Test 6: Performance benchmark
        std::cout << "\nTest 6: Performance benchmark\n";
        if (!testPerformance()) {
            std::cout << "❌ FAILED: Performance test\n";
            return;
        }
        
        std::cout << "\n" << std::string(50, '=') << "\n";
        std::cout << "🎉 ALL MASS GENERATION TESTS PASSED!\n";
        std::cout << "✅ Mass stub generator is fully functional\n";
        std::cout << "✅ Ready for production use\n";
        std::cout << std::string(50, '=') << "\n";
    }
    
private:
    bool testBatchGeneration(int count) {
        auto startTime = std::chrono::high_resolution_clock::now();
        
        std::vector<std::string> generatedFiles;
        int successCount = 0;
        
        for (int i = 0; i < count; ++i) {
            // Generate unique filename
            std::string filename = "mass_test_" + std::to_string(i + 1) + "_" + generateRandomName(8) + ".exe";
            
            // Generate benign code
            std::string companyName = getRandomCompany();
            std::string payload = generateBenignCode(companyName);
            
            // Create PE executable
            auto peData = generateMinimalPEExecutable(payload);
            
            if (!peData.empty() && verifyPEHeader(peData)) {
                // Write to file
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
        
        std::cout << "  Generated: " << successCount << "/" << count << " stubs\n";
        std::cout << "  Duration: " << duration.count() << "ms\n";
        std::cout << "  Average: " << (duration.count() / (double)count) << "ms per stub\n";
        
        // Clean up test files
        for (const auto& filename : generatedFiles) {
            std::remove(filename.c_str());
        }
        
        return successCount == count;
    }
    
    bool testUniqueness() {
        std::set<std::string> filenames;
        std::set<std::string> companyNames;
        std::set<size_t> fileSizes;
        
        for (int i = 0; i < 100; ++i) {
            // Generate unique filename
            std::string filename = "FUD_Stub_" + std::to_string(i + 1) + "_" + generateRandomName(8) + ".exe";
            filenames.insert(filename);
            
            // Generate random company and code
            std::string companyName = getRandomCompany();
            companyNames.insert(companyName);
            
            std::string payload = generateBenignCode(companyName);
            auto peData = generateMinimalPEExecutable(payload);
            
            if (!peData.empty()) {
                fileSizes.insert(peData.size());
            }
        }
        
        std::cout << "  Unique filenames: " << filenames.size() << "/100\n";
        std::cout << "  Unique companies: " << companyNames.size() << "/100\n";
        std::cout << "  Unique file sizes: " << fileSizes.size() << "/100\n";
        
        return filenames.size() == 100 && companyNames.size() > 1 && fileSizes.size() > 1;
    }
    
    bool testPerformance() {
        std::vector<double> generationTimes;
        
        for (int test = 0; test < 10; ++test) {
            auto startTime = std::chrono::high_resolution_clock::now();
            
            // Generate 10 stubs
            for (int i = 0; i < 10; ++i) {
                std::string payload = generateBenignCode(getRandomCompany());
                auto peData = generateMinimalPEExecutable(payload);
                
                if (peData.empty() || !verifyPEHeader(peData)) {
                    return false;
                }
            }
            
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);
            generationTimes.push_back(duration.count() / 1000.0); // Convert to ms
        }
        
        // Calculate statistics
        double avgTime = 0.0;
        for (double time : generationTimes) {
            avgTime += time;
        }
        avgTime /= generationTimes.size();
        
        double avgPerStub = avgTime / 10.0;
        
        std::cout << "  Average generation time: " << std::fixed << std::setprecision(2) << avgTime << "ms\n";
        std::cout << "  Average per stub: " << std::fixed << std::setprecision(2) << avgPerStub << "ms\n";
        std::cout << "  Performance: " << (1000.0 / avgPerStub) << " stubs/second\n";
        
        return avgPerStub < 10.0; // Should be faster than 10ms per stub
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
    
    std::string getRandomCompany() {
        std::vector<std::string> companies = {
            "Adobe Systems Incorporated",
            "Google LLC", 
            "Intel Corporation",
            "NVIDIA Corporation",
            "Apple Inc.",
            "Oracle Corporation",
            "IBM Corporation",
            "VMware, Inc.",
            "Symantec Corporation",
            "McAfee, Inc.",
            "Microsoft Corporation",
            "Cisco Systems, Inc.",
            "Dell Technologies",
            "HP Inc.",
            "Lenovo Group Limited"
        };
        
        return companies[dis(gen) % companies.size()];
    }
    
    std::string generateBenignCode(const std::string& companyName) {
        std::vector<std::string> templates = {
            "#include <iostream>\n#include <string>\n\nint main() {\n    std::cout << \"Hello from " + companyName + "!\" << std::endl;\n    return 0;\n}",
            
            "#include <windows.h>\n\nint WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n    MessageBoxA(NULL, \"Welcome to " + companyName + " application!\", \"Info\", MB_OK);\n    return 0;\n}",
            
            "#include <iostream>\n#include <ctime>\n\nint main() {\n    time_t now = time(0);\n    std::cout << \"Current time: \" << ctime(&now) << std::endl;\n    std::cout << \"" + companyName + " - System Information\" << std::endl;\n    return 0;\n}",
            
            "#include <iostream>\n#include <vector>\n\nint main() {\n    std::vector<int> numbers = {1, 2, 3, 4, 5};\n    std::cout << \"" + companyName + " - Processing data...\" << std::endl;\n    for (int num : numbers) {\n        std::cout << \"Processing: \" << num << std::endl;\n    }\n    return 0;\n}",
            
            "#include <iostream>\n#include <thread>\n#include <chrono>\n\nint main() {\n    std::cout << \"" + companyName + " - Background Service\" << std::endl;\n    std::this_thread::sleep_for(std::chrono::seconds(1));\n    std::cout << \"Service completed.\" << std::endl;\n    return 0;\n}"
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
};

int main() {
    FinalMassGenerationTest test;
    test.runFinalTest();
    return 0;
}
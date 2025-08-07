#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <chrono>
#include <algorithm>
#include <iomanip>
#include <map>

class SampleTester {
private:
    struct TestResult {
        std::string stubName;
        std::string testFile;
        bool isValidPE;
        bool packingSuccessful;
        bool unpackingSuccessful;
        size_t originalSize;
        size_t packedSize;
        double compressionRatio;
        long long packingTime;
        long long unpackingTime;
        bool peIntegrityMaintained;
        std::string errorMessage;
    };
    
    std::vector<TestResult> results;

public:
    bool isValidPE(const std::vector<unsigned char>& data) {
        if (data.size() < 64) return false;
        if (data[0] != 'M' || data[1] != 'Z') return false;
        uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&data[60]);
        if (peOffset >= data.size() - 4) return false;
        if (data[peOffset] != 'P' || data[peOffset + 1] != 'E' || 
            data[peOffset + 2] != 0 || data[peOffset + 3] != 0) return false;
        return true;
    }
    
    std::vector<unsigned char> loadFile(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) return {};
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);
        std::vector<unsigned char> data(size);
        file.read(reinterpret_cast<char*>(data.data()), size);
        return data;
    }
    
    TestResult testStub(const std::string& testFile) {
        TestResult result;
        result.testFile = testFile;
        result.packingSuccessful = false;
        result.unpackingSuccessful = false;
        result.peIntegrityMaintained = false;
        
        auto originalData = loadFile(testFile);
        if (originalData.empty()) {
            result.errorMessage = "Failed to load test file";
            return result;
        }
        
        result.originalSize = originalData.size();
        result.isValidPE = isValidPE(originalData);
        
        if (!result.isValidPE) {
            result.errorMessage = "Input file is not a valid PE";
            return result;
        }
        
        std::string packedFile = "sample_packed.exe";
        std::string unpackedFile = "sample_unpacked.exe";
        
        auto start = std::chrono::high_resolution_clock::now();
        std::string command = "./encryptor stealth " + testFile + " " + packedFile + " testkey123 2>/dev/null";
        int packResult = system(command.c_str());
        auto packEnd = std::chrono::high_resolution_clock::now();
        result.packingTime = std::chrono::duration_cast<std::chrono::microseconds>(packEnd - start).count();
        
        if (packResult == 0) {
            result.packingSuccessful = true;
            auto packedData = loadFile(packedFile);
            if (!packedData.empty()) {
                result.packedSize = packedData.size();
                result.compressionRatio = static_cast<double>(result.packedSize) / result.originalSize;
                
                auto unpackStart = std::chrono::high_resolution_clock::now();
                std::string unpackCommand = "./encryptor unpack " + packedFile + " " + unpackedFile + " testkey123 2>/dev/null";
                int unpackResult = system(unpackCommand.c_str());
                auto unpackEnd = std::chrono::high_resolution_clock::now();
                result.unpackingTime = std::chrono::duration_cast<std::chrono::microseconds>(unpackEnd - unpackStart).count();
                
                if (unpackResult == 0) {
                    result.unpackingSuccessful = true;
                    auto unpackedData = loadFile(unpackedFile);
                    if (!unpackedData.empty()) {
                        result.peIntegrityMaintained = isValidPE(unpackedData);
                    }
                }
            }
        }
        
        std::filesystem::remove(packedFile);
        std::filesystem::remove(unpackedFile);
        return result;
    }
    
    void runSampleTests() {
        std::cout << "Running Sample PE Stub Testing\n";
        std::cout << "==============================\n\n";
        
        std::vector<std::string> testFiles = {
            "test_pe_basic_1.exe", "test_pe_basic_2.exe", 
            "test_pe_complex_1.exe", "test_pe_complex_2.exe"
        };
        
        for (const auto& testFile : testFiles) {
            if (!std::filesystem::exists(testFile)) {
                std::cout << "Warning: " << testFile << " not found\n";
                continue;
            }
            
            std::cout << "Testing: " << testFile << " ... ";
            auto result = testStub(testFile);
            results.push_back(result);
            
            if (result.packingSuccessful && result.unpackingSuccessful && result.peIntegrityMaintained) {
                std::cout << "✓ SUCCESS";
            } else {
                std::cout << "✗ FAILED (" << result.errorMessage << ")";
            }
            std::cout << std::endl;
        }
        
        generateReport();
    }
    
    void generateReport() {
        std::cout << "\n=== SAMPLE TEST RESULTS ===\n" << std::endl;
        
        int successful = 0;
        double avgPackTime = 0, avgUnpackTime = 0, avgCompression = 0;
        
        for (const auto& result : results) {
            if (result.packingSuccessful && result.unpackingSuccessful && result.peIntegrityMaintained) {
                successful++;
            }
            avgPackTime += result.packingTime;
            avgUnpackTime += result.unpackingTime;
            if (result.compressionRatio > 0) {
                avgCompression += result.compressionRatio;
            }
        }
        
        std::cout << "Success Rate: " << successful << "/" << results.size() 
                  << " (" << std::fixed << std::setprecision(1) 
                  << (100.0 * successful / results.size()) << "%)" << std::endl;
        std::cout << "Average Pack Time: " << std::setprecision(2) 
                  << (avgPackTime / results.size() / 1000.0) << " ms" << std::endl;
        std::cout << "Average Unpack Time: " << std::setprecision(2) 
                  << (avgUnpackTime / results.size() / 1000.0) << " ms" << std::endl;
        std::cout << "Average Compression Ratio: " << std::setprecision(3) 
                  << (avgCompression / results.size()) << std::endl;
    }
};

int main() {
    SampleTester tester;
    tester.runSampleTests();
    return 0;
}
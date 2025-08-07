#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <chrono>
#include <algorithm>
#include <iomanip>
#include <map>

class ComprehensiveTester {
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
        long long packingTime; // microseconds
        long long unpackingTime; // microseconds
        bool peIntegrityMaintained;
        std::string errorMessage;
    };
    
    std::vector<TestResult> results;

public:
    bool isValidPE(const std::vector<unsigned char>& data) {
        if (data.size() < 64) return false;
        
        // Check DOS header signature
        if (data[0] != 'M' || data[1] != 'Z') return false;
        
        // Get PE header offset
        if (data.size() < 64) return false;
        uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&data[60]);
        if (peOffset >= data.size() - 4) return false;
        
        // Check PE signature
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
    
    bool saveFile(const std::string& filename, const std::vector<unsigned char>& data) {
        std::ofstream file(filename, std::ios::binary);
        if (!file) return false;
        
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        return file.good();
    }
    
    TestResult testStubWithFile(const std::string& stubFile, const std::string& testFile) {
        TestResult result;
        result.stubName = stubFile;
        result.testFile = testFile;
        result.packingSuccessful = false;
        result.unpackingSuccessful = false;
        result.peIntegrityMaintained = false;
        result.errorMessage = "";
        
        // Load original test file
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
        
        // Test with our encryptor
        std::string packedFile = "temp_packed_" + std::filesystem::path(testFile).stem().string() + ".exe";
        std::string unpackedFile = "temp_unpacked_" + std::filesystem::path(testFile).stem().string() + ".exe";
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Test stealth packing
        std::string command = "./encryptor stealth " + testFile + " " + packedFile + " testkey123";
        int packResult = system(command.c_str());
        
        auto packEnd = std::chrono::high_resolution_clock::now();
        result.packingTime = std::chrono::duration_cast<std::chrono::microseconds>(packEnd - start).count();
        
        if (packResult == 0) {
            result.packingSuccessful = true;
            
            // Check packed file
            auto packedData = loadFile(packedFile);
            if (!packedData.empty()) {
                result.packedSize = packedData.size();
                result.compressionRatio = static_cast<double>(result.packedSize) / result.originalSize;
                
                // Test unpacking
                auto unpackStart = std::chrono::high_resolution_clock::now();
                
                std::string unpackCommand = "./encryptor unpack " + packedFile + " " + unpackedFile + " testkey123";
                int unpackResult = system(unpackCommand.c_str());
                
                auto unpackEnd = std::chrono::high_resolution_clock::now();
                result.unpackingTime = std::chrono::duration_cast<std::chrono::microseconds>(unpackEnd - unpackStart).count();
                
                if (unpackResult == 0) {
                    result.unpackingSuccessful = true;
                    
                    // Verify PE integrity
                    auto unpackedData = loadFile(unpackedFile);
                    if (!unpackedData.empty()) {
                        result.peIntegrityMaintained = isValidPE(unpackedData);
                        
                        // Check if data is roughly the same size (allowing for some variation)
                        double sizeRatio = static_cast<double>(unpackedData.size()) / originalData.size();
                        if (sizeRatio < 0.8 || sizeRatio > 1.2) {
                            result.errorMessage += "Size mismatch after unpack; ";
                        }
                    } else {
                        result.errorMessage += "Failed to load unpacked file; ";
                    }
                } else {
                    result.errorMessage += "Unpacking failed; ";
                }
            } else {
                result.errorMessage += "Failed to load packed file; ";
            }
        } else {
            result.errorMessage += "Packing failed; ";
        }
        
        // Cleanup temporary files
        std::filesystem::remove(packedFile);
        std::filesystem::remove(unpackedFile);
        
        return result;
    }
    
    void runComprehensiveTests() {
        std::cout << "Starting Comprehensive PE Stub Testing\n";
        std::cout << "======================================\n\n";
        
        // Get list of test PE files
        std::vector<std::string> testFiles;
        for (int i = 1; i <= 5; ++i) {
            testFiles.push_back("test_pe_basic_" + std::to_string(i) + ".exe");
            testFiles.push_back("test_pe_complex_" + std::to_string(i) + ".exe");
        }
        
        // Get list of stub files
        std::vector<std::string> stubFiles;
        for (int i = 1; i <= 100; ++i) {
            std::string stubFile = "advanced_stub_" + std::string(3 - std::to_string(i).length(), '0') + 
                                 std::to_string(i) + "_Variant" + std::to_string(i) + ".exe";
            if (std::filesystem::exists(stubFile)) {
                stubFiles.push_back(stubFile);
            }
        }
        
        std::cout << "Found " << stubFiles.size() << " stub files and " << testFiles.size() << " test files\n";
        std::cout << "Total tests to run: " << (stubFiles.size() * testFiles.size()) << "\n\n";
        
        int testCount = 0;
        int totalTests = stubFiles.size() * testFiles.size();
        
        // Test each stub with each test file
        for (const auto& testFile : testFiles) {
            if (!std::filesystem::exists(testFile)) {
                std::cout << "Warning: Test file " << testFile << " not found, skipping...\n";
                continue;
            }
            
            std::cout << "Testing with file: " << testFile << std::endl;
            
            for (const auto& stubFile : stubFiles) {
                testCount++;
                
                if (testCount % 50 == 0) {
                    std::cout << "Progress: " << testCount << "/" << totalTests << " tests completed ("
                              << std::fixed << std::setprecision(1) 
                              << (100.0 * testCount / totalTests) << "%)" << std::endl;
                }
                
                auto result = testStubWithFile(stubFile, testFile);
                results.push_back(result);
            }
        }
        
        std::cout << "\nAll tests completed! Generating analysis...\n" << std::endl;
        generateAnalysisReport();
    }
    
    void generateAnalysisReport() {
        std::cout << "=== COMPREHENSIVE TEST ANALYSIS ===\n" << std::endl;
        
        // Overall statistics
        int totalTests = results.size();
        int successfulPacks = 0;
        int successfulUnpacks = 0;
        int peIntegrityMaintained = 0;
        double totalPackTime = 0;
        double totalUnpackTime = 0;
        double totalCompressionRatio = 0;
        int validCompressions = 0;
        
        for (const auto& result : results) {
            if (result.packingSuccessful) successfulPacks++;
            if (result.unpackingSuccessful) successfulUnpacks++;
            if (result.peIntegrityMaintained) peIntegrityMaintained++;
            
            totalPackTime += result.packingTime;
            totalUnpackTime += result.unpackingTime;
            
            if (result.packingSuccessful && result.compressionRatio > 0) {
                totalCompressionRatio += result.compressionRatio;
                validCompressions++;
            }
        }
        
        std::cout << "Overall Statistics:" << std::endl;
        std::cout << "  Total tests: " << totalTests << std::endl;
        std::cout << "  Successful packing: " << successfulPacks << "/" << totalTests 
                  << " (" << std::fixed << std::setprecision(1) << (100.0 * successfulPacks / totalTests) << "%)" << std::endl;
        std::cout << "  Successful unpacking: " << successfulUnpacks << "/" << totalTests 
                  << " (" << (100.0 * successfulUnpacks / totalTests) << "%)" << std::endl;
        std::cout << "  PE integrity maintained: " << peIntegrityMaintained << "/" << totalTests 
                  << " (" << (100.0 * peIntegrityMaintained / totalTests) << "%)" << std::endl;
        
        if (validCompressions > 0) {
            std::cout << "  Average compression ratio: " << std::setprecision(3) 
                      << (totalCompressionRatio / validCompressions) << std::endl;
        }
        
        std::cout << "  Average packing time: " << std::setprecision(2) 
                  << (totalPackTime / totalTests / 1000.0) << " ms" << std::endl;
        std::cout << "  Average unpacking time: " << std::setprecision(2) 
                  << (totalUnpackTime / totalTests / 1000.0) << " ms" << std::endl;
        
        // Performance analysis by file type
        std::cout << "\nPerformance by File Type:" << std::endl;
        analyzeByFileType("basic");
        analyzeByFileType("complex");
        
        // Top performing stubs
        std::cout << "\nTop 10 Most Reliable Stubs:" << std::endl;
        analyzeTopStubs();
        
        // Error analysis
        std::cout << "\nError Analysis:" << std::endl;
        analyzeErrors();
        
        // Size analysis
        std::cout << "\nSize Analysis:" << std::endl;
        analyzeSizes();
        
        // Save detailed results to CSV
        saveResultsToCSV();
    }
    
    void analyzeByFileType(const std::string& fileType) {
        std::vector<TestResult> filtered;
        std::copy_if(results.begin(), results.end(), std::back_inserter(filtered),
                    [&fileType](const TestResult& r) { return r.testFile.find(fileType) != std::string::npos; });
        
        if (filtered.empty()) return;
        
        int successful = 0;
        double avgCompression = 0;
        int validCompressions = 0;
        
        for (const auto& result : filtered) {
            if (result.packingSuccessful && result.unpackingSuccessful && result.peIntegrityMaintained) {
                successful++;
            }
            if (result.packingSuccessful && result.compressionRatio > 0) {
                avgCompression += result.compressionRatio;
                validCompressions++;
            }
        }
        
        std::cout << "  " << fileType << " files: " << successful << "/" << filtered.size() 
                  << " (" << std::fixed << std::setprecision(1) << (100.0 * successful / filtered.size()) << "%) success rate";
        
        if (validCompressions > 0) {
            std::cout << ", avg compression: " << std::setprecision(3) << (avgCompression / validCompressions);
        }
        std::cout << std::endl;
    }
    
    void analyzeTopStubs() {
        std::map<std::string, int> stubScores;
        
        for (const auto& result : results) {
            int score = 0;
            if (result.packingSuccessful) score += 1;
            if (result.unpackingSuccessful) score += 1;
            if (result.peIntegrityMaintained) score += 1;
            
            stubScores[result.stubName] += score;
        }
        
        std::vector<std::pair<std::string, int>> sortedStubs(stubScores.begin(), stubScores.end());
        std::sort(sortedStubs.begin(), sortedStubs.end(), 
                 [](const auto& a, const auto& b) { return a.second > b.second; });
        
        int count = 0;
        for (const auto& stub : sortedStubs) {
            if (count >= 10) break;
            std::cout << "  " << (count + 1) << ". " << stub.first 
                      << " (score: " << stub.second << "/" << (results.size() / 100 * 3) << ")" << std::endl;
            count++;
        }
    }
    
    void analyzeErrors() {
        std::map<std::string, int> errorCounts;
        
        for (const auto& result : results) {
            if (!result.errorMessage.empty()) {
                errorCounts[result.errorMessage]++;
            }
        }
        
        for (const auto& error : errorCounts) {
            std::cout << "  " << error.first << ": " << error.second << " occurrences" << std::endl;
        }
    }
    
    void analyzeSizes() {
        if (results.empty()) return;
        
        std::vector<size_t> originalSizes, packedSizes;
        std::vector<double> compressionRatios;
        
        for (const auto& result : results) {
            if (result.packingSuccessful) {
                originalSizes.push_back(result.originalSize);
                packedSizes.push_back(result.packedSize);
                if (result.compressionRatio > 0) {
                    compressionRatios.push_back(result.compressionRatio);
                }
            }
        }
        
        if (!originalSizes.empty()) {
            auto minOrig = *std::min_element(originalSizes.begin(), originalSizes.end());
            auto maxOrig = *std::max_element(originalSizes.begin(), originalSizes.end());
            auto minPacked = *std::min_element(packedSizes.begin(), packedSizes.end());
            auto maxPacked = *std::max_element(packedSizes.begin(), packedSizes.end());
            
            std::cout << "  Original sizes: " << minOrig << " - " << maxOrig << " bytes" << std::endl;
            std::cout << "  Packed sizes: " << minPacked << " - " << maxPacked << " bytes" << std::endl;
        }
        
        if (!compressionRatios.empty()) {
            auto minRatio = *std::min_element(compressionRatios.begin(), compressionRatios.end());
            auto maxRatio = *std::max_element(compressionRatios.begin(), compressionRatios.end());
            std::cout << "  Compression ratios: " << std::fixed << std::setprecision(3) 
                      << minRatio << " - " << maxRatio << std::endl;
        }
    }
    
    void saveResultsToCSV() {
        std::ofstream csv("test_results.csv");
        if (!csv) return;
        
        csv << "StubName,TestFile,PackingSuccessful,UnpackingSuccessful,PEIntegrityMaintained,"
            << "OriginalSize,PackedSize,CompressionRatio,PackingTime,UnpackingTime,ErrorMessage\n";
        
        for (const auto& result : results) {
            csv << result.stubName << ","
                << result.testFile << ","
                << (result.packingSuccessful ? "1" : "0") << ","
                << (result.unpackingSuccessful ? "1" : "0") << ","
                << (result.peIntegrityMaintained ? "1" : "0") << ","
                << result.originalSize << ","
                << result.packedSize << ","
                << std::fixed << std::setprecision(4) << result.compressionRatio << ","
                << result.packingTime << ","
                << result.unpackingTime << ","
                << "\"" << result.errorMessage << "\"\n";
        }
        
        std::cout << "\nDetailed results saved to test_results.csv" << std::endl;
    }
};

int main() {
    std::cout << "Comprehensive PE Stub Testing Suite\n";
    std::cout << "===================================\n\n";
    
    ComprehensiveTester tester;
    tester.runComprehensiveTests();
    
    return 0;
}
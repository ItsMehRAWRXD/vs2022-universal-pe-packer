#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <algorithm>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <thread>

// Cross-platform compatibility
#ifdef _WIN32
    #include <windows.h>
    #define SYSTEM_CLEAR "cls"
#else
    #include <unistd.h>
    #include <sys/stat.h>
    #define SYSTEM_CLEAR "clear"
#endif

class AdvancedRandomEngine {
public:
    std::random_device rd;
    std::mt19937 gen;
    std::uniform_int_distribution<> dis;
    
    AdvancedRandomEngine() : gen(rd()), dis(0, 255) {
        auto now = std::chrono::high_resolution_clock::now();
        auto nanos = now.time_since_epoch().count();
        gen.seed(static_cast<unsigned int>(nanos ^ rd()));
    }
    
    std::string generateRandomName(int length = 8) {
        const std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        std::uniform_int_distribution<> charDis(0, static_cast<int>(chars.length() - 1));
        std::string result;
        for (int i = 0; i < length; ++i) {
            result += chars[charDis(gen)];
        }
        return result;
    }
    
    uint32_t generateRandomDWORD() {
        std::uniform_int_distribution<uint32_t> dwordDis;
        return dwordDis(gen);
    }
};

class TimestampEngine {
private:
    AdvancedRandomEngine randomEngine;
    
public:
    uint32_t generateRealisticTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto epoch = now.time_since_epoch();
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(epoch).count();
        
        // Generate timestamp between 6 months and 3 years ago
        std::uniform_int_distribution<> ageDis(6 * 30 * 24 * 3600, 3 * 365 * 24 * 3600);
        int ageInSeconds = ageDis(randomEngine.gen);
        
        return static_cast<uint32_t>(seconds - ageInSeconds);
    }
};

class SuperBenignBehavior {
private:
    AdvancedRandomEngine randomEngine;
    
public:
    std::string generateBenignCode(const std::string& companyName) {
        std::uniform_int_distribution<> delayDis(2000, 5000);
        int startupDelay = delayDis(randomEngine.gen);
        
        std::string code = R"(
#include <iostream>
#include <thread>
#include <chrono>
)" + (std::string)
#ifdef _WIN32
R"(#include <windows.h>

int main() {
    // Realistic startup delay
    std::this_thread::sleep_for(std::chrono::milliseconds()" + std::to_string(startupDelay) + R"());
    
    // Display benign message
    MessageBoxA(NULL, 
               ")" + companyName + R"( Application\n\nSystem check completed successfully.\n\nVersion: 1.0.0", 
               ")" + companyName + R"(", 
               MB_OK | MB_ICONINFORMATION);
    
    return 0;
})"
#else
R"(
int main() {
    // Realistic startup delay
    std::this_thread::sleep_for(std::chrono::milliseconds()" + std::to_string(startupDelay) + R"());
    
    // Display benign message
    std::cout << ")" + companyName + R"( Application" << std::endl;
    std::cout << "System check completed successfully." << std::endl;
    std::cout << "Version: 1.0.0" << std::endl;
    
    return 0;
})"
#endif
;
        return code;
    }
};

class CompilerDetector {
public:
    struct CompilerInfo {
        std::string path;
        std::string version;
        bool found;
    };
    
    static CompilerInfo detectCompiler() {
        CompilerInfo info = { "", "", false };
        
#ifdef _WIN32
        // Windows compiler detection
        std::vector<std::string> compilers = {"cl", "g++", "clang++"};
#else
        // Linux compiler detection
        std::vector<std::string> compilers = {"g++", "clang++", "c++"};
#endif
        
        for (const auto& compiler : compilers) {
            if (testCompiler(compiler)) {
                info.path = compiler;
                info.version = getCompilerVersion(compiler);
                info.found = true;
                break;
            }
        }
        
        return info;
    }
    
private:
    static bool testCompiler(const std::string& compiler) {
        std::string testCmd = compiler + " --version > /dev/null 2>&1";
#ifdef _WIN32
        testCmd = compiler + " > nul 2>&1";
#endif
        return system(testCmd.c_str()) == 0;
    }
    
    static std::string getCompilerVersion(const std::string& compiler) {
        // Simplified version detection
        return "detected";
    }
};

class TestStealthPacker {
private:
    AdvancedRandomEngine randomEngine;
    TimestampEngine timestampEngine;
    SuperBenignBehavior benignBehavior;
    
    struct CompanyProfile {
        std::string name;
        std::string description;
    };
    
    std::vector<CompanyProfile> companyProfiles = {
        {"Microsoft Corporation", "Leading technology company"},
        {"Adobe Systems Incorporated", "Creative software solutions"},
        {"Google LLC", "Internet services and products"},
        {"Intel Corporation", "Semiconductor solutions"},
        {"NVIDIA Corporation", "Graphics technology"}
    };
    
public:
    bool createTestExecutable(const std::string& inputPath, const std::string& outputPath, int companyIndex) {
        try {
            std::cout << "🔥 TESTING STEALTH PACKER LOGIC 🔥" << std::endl;
            std::cout << "=====================================\n" << std::endl;
            
            // Check input file exists
            std::ifstream inputFile(inputPath);
            if (!inputFile.is_open()) {
                std::cout << "❌ Input file not found: " << inputPath << std::endl;
                return false;
            }
            inputFile.close();
            
            // Get company info
            const auto& company = companyProfiles[companyIndex % companyProfiles.size()];
            std::cout << "✅ Company Profile: " << company.name << std::endl;
            
            // Generate realistic timestamp
            uint32_t timestamp = timestampEngine.generateRealisticTimestamp();
            auto timeT = static_cast<time_t>(timestamp);
            std::cout << "✅ Generated Timestamp: " << std::ctime(&timeT);
            
            // Generate benign code
            std::string benignCode = benignBehavior.generateBenignCode(company.name);
            std::cout << "✅ Generated " << benignCode.length() << " bytes of benign code" << std::endl;
            
            // Create temporary source file
            std::string tempSource = "temp_" + randomEngine.generateRandomName() + ".cpp";
            std::ofstream sourceFile(tempSource);
            if (!sourceFile.is_open()) {
                std::cout << "❌ Failed to create temporary source file" << std::endl;
                return false;
            }
            sourceFile << benignCode;
            sourceFile.close();
            std::cout << "✅ Created temporary source: " << tempSource << std::endl;
            
            // Detect compiler
            auto compilerInfo = CompilerDetector::detectCompiler();
            if (!compilerInfo.found) {
                std::cout << "❌ No compiler found" << std::endl;
                remove(tempSource.c_str());
                return false;
            }
            std::cout << "✅ Compiler detected: " << compilerInfo.path << std::endl;
            
            // Build compilation command
            std::string compileCmd;
#ifdef _WIN32
            compileCmd = compilerInfo.path + " /nologo /O2 /DNDEBUG /MD ";
            compileCmd += "/Fe\"" + outputPath + "\" ";
            compileCmd += "\"" + tempSource + "\" ";
            compileCmd += "/link /MACHINE:X64 /SUBSYSTEM:WINDOWS user32.lib kernel32.lib";
#else
            compileCmd = compilerInfo.path + " -O2 -DNDEBUG ";
            compileCmd += "\"" + tempSource + "\" -o \"" + outputPath + "\"";
#endif
            
            std::cout << "✅ Compilation command: " << compileCmd << std::endl;
            
            // Execute compilation
            std::cout << "🔧 Compiling..." << std::endl;
            int result = system(compileCmd.c_str());
            
            // Clean up
            remove(tempSource.c_str());
            
            if (result == 0) {
                std::cout << "🎉 SUCCESS! Executable created: " << outputPath << std::endl;
                
                // Verify output file exists
                std::ifstream testOutput(outputPath);
                if (testOutput.is_open()) {
                    testOutput.close();
                    std::cout << "✅ Output file verified!" << std::endl;
                    return true;
                } else {
                    std::cout << "❌ Output file not found after compilation" << std::endl;
                    return false;
                }
            } else {
                std::cout << "❌ Compilation failed with exit code: " << result << std::endl;
                return false;
            }
            
        } catch (const std::exception& e) {
            std::cout << "❌ Exception: " << e.what() << std::endl;
            return false;
        }
    }
    
    void runTests() {
        std::cout << "🚀 ULTIMATE STEALTH PACKER TEST SUITE 🚀" << std::endl;
        std::cout << "=========================================\n" << std::endl;
        
        // Test 1: Timestamp generation
        std::cout << "TEST 1: Timestamp Generation" << std::endl;
        for (int i = 0; i < 5; i++) {
            uint32_t timestamp = timestampEngine.generateRealisticTimestamp();
            auto timeT = static_cast<time_t>(timestamp);
            std::cout << "  " << (i+1) << ". " << std::ctime(&timeT);
        }
        std::cout << std::endl;
        
        // Test 2: Random name generation
        std::cout << "TEST 2: Random Name Generation" << std::endl;
        for (int i = 0; i < 5; i++) {
            std::cout << "  " << (i+1) << ". " << randomEngine.generateRandomName(12) << std::endl;
        }
        std::cout << std::endl;
        
        // Test 3: Company profiles
        std::cout << "TEST 3: Company Profiles" << std::endl;
        for (size_t i = 0; i < companyProfiles.size(); i++) {
            std::cout << "  " << (i+1) << ". " << companyProfiles[i].name << std::endl;
        }
        std::cout << std::endl;
        
        // Test 4: Code generation
        std::cout << "TEST 4: Benign Code Generation" << std::endl;
        std::string testCode = benignBehavior.generateBenignCode("Test Company");
        std::cout << "  Generated code length: " << testCode.length() << " bytes" << std::endl;
        std::cout << "  First 100 chars: " << testCode.substr(0, 100) << "..." << std::endl;
        std::cout << std::endl;
        
        std::cout << "🎯 ALL TESTS COMPLETED!" << std::endl;
    }
    
    std::vector<CompanyProfile> getCompanyProfiles() const {
        return companyProfiles;
    }
};

int main() {
    system(SYSTEM_CLEAR);
    
    TestStealthPacker packer;
    
    std::cout << "🔥 CROSS-PLATFORM STEALTH PACKER TEST 🔥" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    // Run basic tests first
    packer.runTests();
    
    std::cout << "\n🎯 REAL COMPILATION TEST:" << std::endl;
    std::cout << "=========================" << std::endl;
    
    // Create a dummy input file for testing
    std::string inputFile = "test_input.txt";
    std::ofstream input(inputFile);
    input << "Test input file content";
    input.close();
    
    // Test executable creation
    std::string outputFile = "test_output";
#ifdef _WIN32
    outputFile += ".exe";
#endif
    
    auto companies = packer.getCompanyProfiles();
    std::cout << "\nTesting with different companies:" << std::endl;
    
    for (size_t i = 0; i < std::min(companies.size(), size_t(3)); i++) {
        std::cout << "\n--- Test " << (i+1) << ": " << companies[i].name << " ---" << std::endl;
        std::string testOutput = "test_" + std::to_string(i+1) + "_output";
#ifdef _WIN32
        testOutput += ".exe";
#endif
        
        bool success = packer.createTestExecutable(inputFile, testOutput, static_cast<int>(i));
        
        if (success) {
            std::cout << "🎉 SUCCESSFUL TEST #" << (i+1) << std::endl;
        } else {
            std::cout << "❌ FAILED TEST #" << (i+1) << std::endl;
        }
    }
    
    // Cleanup
    remove(inputFile.c_str());
    
    std::cout << "\n🏆 TEST SUITE COMPLETED!" << std::endl;
    std::cout << "Now ready for Windows implementation!" << std::endl;
    
    return 0;
}
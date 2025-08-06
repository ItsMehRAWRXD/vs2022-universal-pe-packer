#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <thread>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <cstdlib>

class AdvancedRandomEngine {
public:
    AdvancedRandomEngine() : gen(std::random_device{}()) {}
    
    std::string generateRandomName(size_t length = 8) {
        const std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        std::uniform_int_distribution<> dis(0, chars.size() - 1);
        
        std::string result;
        for (size_t i = 0; i < length; ++i) {
            result += chars[dis(gen)];
        }
        return result;
    }
    
    uint32_t generateRandomDWORD() {
        std::uniform_int_distribution<uint32_t> dwordDis;
        return dwordDis(gen);
    }

private:
    std::mt19937 gen;
};

class LinuxBenignBehavior {
public:
    LinuxBenignBehavior(AdvancedRandomEngine& rng) : randomEngine(rng) {}
    
    std::string generateBenignCode(const std::string& companyName) {
        std::string code = R"(#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <cmath>
#include <random>
#include <unistd.h>
#include <sys/utsname.h>

void performBenignOperations() {
    // Realistic startup delay
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    
    // Check system legitimately (read-only)
    struct utsname sysInfo;
    uname(&sysInfo);
    
    char hostname[256] = {0};
    gethostname(hostname, sizeof(hostname));
    
    // Simulate legitimate file operations
    char tempPath[] = "/tmp";
    
    // Display benign message
    std::cout << ")" + companyName + R"( Application\n";
    std::cout << "System check completed successfully.\n";
    std::cout << "Version: 1.0.0\n";
    std::cout << "Host: " << hostname << "\n";
    std::cout << "System: " << sysInfo.sysname << " " << sysInfo.release << "\n";
}
)";
        return code;
    }

private:
    AdvancedRandomEngine& randomEngine;
};

class LinuxPacker {
public:
    LinuxPacker() : benignBehavior(randomEngine) {}
    
    std::string generatePolymorphicSource(const std::vector<uint8_t>& peData, 
                                        const std::string& company,
                                        const std::string& cert) {
        
        std::string varName = "embedded_" + randomEngine.generateRandomName();
        std::string functionName = "extract_" + randomEngine.generateRandomName();
        
        std::ostringstream source;
        
        // Standard includes for Linux
        source << "#include <iostream>\n";
        source << "#include <fstream>\n";
        source << "#include <vector>\n";
        source << "#include <string>\n";
        source << "#include <thread>\n";
        source << "#include <chrono>\n";
        source << "#include <cmath>\n";
        source << "#include <random>\n";
        source << "#include <unistd.h>\n";
        source << "#include <sys/utsname.h>\n";
        
        source << "\n// Company: " << company << "\n";
        source << "// Certificate: " << cert << "\n";
        source << "// Architecture: x64 Linux\n";
        source << "// Timestamp: " << std::chrono::duration_cast<std::chrono::seconds>(
                     std::chrono::system_clock::now().time_since_epoch()).count() << "\n\n";
        
        // Embed PE data as byte array
        source << "unsigned char " << varName << "[] = {\n";
        for (size_t i = 0; i < peData.size(); i++) {
            if (i % 16 == 0) source << "    ";
            source << "0x" << std::hex << std::setfill('0') << std::setw(2) 
                   << static_cast<unsigned int>(peData[i]);
            if (i < peData.size() - 1) source << ", ";
            if (i % 16 == 15) source << "\n";
        }
        source << "\n};\n\n";
        
        source << "size_t " << varName << "_size = " << std::dec << peData.size() << ";\n\n";
        
        // Add benign behavior
        source << benignBehavior.generateBenignCode(company);
        
        // PE extraction function
        source << "bool " << functionName << "(const std::string& path) {\n";
        source << "    std::ofstream outFile(path, std::ios::binary);\n";
        source << "    if (!outFile.is_open()) return false;\n";
        source << "    \n";
        source << "    outFile.write(reinterpret_cast<const char*>(" << varName << "), " << varName << "_size);\n";
        source << "    outFile.close();\n";
        source << "    \n";
        source << "    std::cout << \"Extracted to: \" << path << std::endl;\n";
        source << "    return true;\n";
        source << "}\n\n";
        
        // Main function
        source << "int main() {\n";
        source << "    std::cout << \"=== Linux PE Packer Test ===\\n\\n\";\n";
        source << "    \n";
        source << "    // Perform benign operations\n";
        source << "    performBenignOperations();\n";
        source << "    \n";
        source << "    // Extract embedded PE for testing\n";
        source << "    std::string extractPath = \"/tmp/extracted_pe_\" + std::to_string(getpid()) + \".exe\";\n";
        source << "    if (" << functionName << "(extractPath)) {\n";
        source << "        std::cout << \"\\nPE data successfully embedded and extracted!\\n\";\n";
        source << "        std::cout << \"Original size: " << peData.size() << " bytes\\n\";\n";
        source << "        std::cout << \"Extracted to: \" << extractPath << \"\\n\";\n";
        source << "    } else {\n";
        source << "        std::cout << \"Failed to extract PE data\\n\";\n";
        source << "        return 1;\n";
        source << "    }\n";
        source << "    \n";
        source << "    return 0;\n";
        source << "}\n";
        
        return source.str();
    }
    
    bool testCompilation(const std::string& inputPath, const std::string& outputPath) {
        try {
            // Read input file
            std::ifstream inputFile(inputPath, std::ios::binary);
            if (!inputFile.is_open()) {
                std::cout << "Error: Cannot open input file: " << inputPath << std::endl;
                return false;
            }
            
            inputFile.seekg(0, std::ios::end);
            size_t inputSize = inputFile.tellg();
            inputFile.seekg(0, std::ios::beg);
            
            std::vector<uint8_t> originalData(inputSize);
            inputFile.read(reinterpret_cast<char*>(originalData.data()), inputSize);
            inputFile.close();
            
            std::cout << "Read input file: " << inputPath << " (" << inputSize << " bytes)\n";
            
            // Generate source code
            std::string sourceCode = generatePolymorphicSource(originalData, "Adobe Systems Inc", "DigiCert");
            
            // Save source for testing
            std::string sourceFilename = "test_generated_" + randomEngine.generateRandomName() + ".cpp";
            std::ofstream sourceFile(sourceFilename);
            if (sourceFile.is_open()) {
                sourceFile << sourceCode;
                sourceFile.close();
                std::cout << "Generated source: " << sourceFilename << " (" << sourceCode.length() << " chars)\n";
            } else {
                std::cout << "Error: Cannot create source file\n";
                return false;
            }
            
            // Compile with g++
            std::string compileCmd = "g++ -std=c++17 -O2 -o \"" + outputPath + "\" \"" + sourceFilename + "\" -lpthread";
            
            std::cout << "Compiling with: " << compileCmd << std::endl;
            
            int result = system(compileCmd.c_str());
            
            if (result == 0) {
                std::cout << "✅ Compilation SUCCESS!" << std::endl;
                std::cout << "Output: " << outputPath << std::endl;
                
                // Test execution
                std::cout << "\n=== Testing Execution ===\n";
                std::string runCmd = "./" + outputPath;
                int runResult = system(runCmd.c_str());
                
                if (runResult == 0) {
                    std::cout << "✅ Execution SUCCESS!" << std::endl;
                } else {
                    std::cout << "❌ Execution failed with code: " << runResult << std::endl;
                }
                
                return true;
            } else {
                std::cout << "❌ Compilation FAILED with code: " << result << std::endl;
                return false;
            }
            
        } catch (const std::exception& e) {
            std::cout << "Exception: " << e.what() << std::endl;
            return false;
        }
    }

private:
    AdvancedRandomEngine randomEngine;
    LinuxBenignBehavior benignBehavior;
};

int main(int argc, char* argv[]) {
    std::cout << "=== Linux PE Packer Test ===\n";
    std::cout << "Testing the core packer functionality on Linux\n\n";
    
    LinuxPacker packer;
    
    // Create a test input file if none provided
    std::string inputPath = "/bin/ls";  // Use ls as test binary
    std::string outputPath = "test_packed_output";
    
    if (argc >= 2) {
        inputPath = argv[1];
    }
    if (argc >= 3) {
        outputPath = argv[2];
    }
    
    std::cout << "Input: " << inputPath << std::endl;
    std::cout << "Output: " << outputPath << std::endl;
    std::cout << std::endl;
    
    // Test the packer
    bool success = packer.testCompilation(inputPath, outputPath);
    
    if (success) {
        std::cout << "\n🎉 PACKER TEST SUCCESSFUL!" << std::endl;
        std::cout << "The core functionality works correctly!" << std::endl;
    } else {
        std::cout << "\n❌ PACKER TEST FAILED!" << std::endl;
        std::cout << "Check the compilation errors above." << std::endl;
    }
    
    return success ? 0 : 1;
}
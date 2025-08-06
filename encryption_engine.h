#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <random>
#include <cstdint>

#pragma comment(lib, "advapi32.lib")

class EncryptionEngine {
private:
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
    std::mt19937 rng;

public:
    enum class Method {
        XOR,
        AES,
        CHACHA20
    };

    EncryptionEngine() : rng(std::random_device{}()) {
        generateRandomKey();
        generateRandomIV();
    }

    // Generate random 32-byte key
    void generateRandomKey() {
        key.resize(32);
        for (auto& byte : key) {
            byte = static_cast<uint8_t>(rng() & 0xFF);
        }
    }

    // Generate random 16-byte IV
    void generateRandomIV() {
        iv.resize(16);
        for (auto& byte : iv) {
            byte = static_cast<uint8_t>(rng() & 0xFF);
        }
    }

    // XOR Encryption (Simple but effective)
    std::vector<uint8_t> xorEncrypt(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> encrypted = data;
        for (size_t i = 0; i < encrypted.size(); ++i) {
            encrypted[i] ^= key[i % key.size()];
        }
        return encrypted;
    }

    std::vector<uint8_t> xorDecrypt(const std::vector<uint8_t>& encrypted) {
        return xorEncrypt(encrypted); // XOR is symmetric
    }

    // AES Encryption using Windows CryptoAPI
    std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t>& data) {
        HCRYPTPROV hProv = 0;
        HCRYPTKEY hKey = 0;
        std::vector<uint8_t> encrypted;

        try {
            // Acquire crypto context
            if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                throw std::runtime_error("Failed to acquire crypto context");
            }

            // Create key blob
            struct {
                BLOBHEADER hdr;
                DWORD keySize;
                BYTE keyData[32];
            } keyBlob;

            keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
            keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
            keyBlob.hdr.reserved = 0;
            keyBlob.hdr.aiKeyAlg = CALG_AES_256;
            keyBlob.keySize = 32;
            memcpy(keyBlob.keyData, key.data(), 32);

            // Import key
            if (!CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
                throw std::runtime_error("Failed to import AES key");
            }

            // Set IV
            if (!CryptSetKeyParam(hKey, KP_IV, iv.data(), 0)) {
                throw std::runtime_error("Failed to set IV");
            }

            // Prepare data for encryption
            encrypted = data;
            DWORD dataLen = static_cast<DWORD>(encrypted.size());
            DWORD bufferLen = dataLen + 16; // Extra space for padding
            encrypted.resize(bufferLen);

            // Encrypt
            if (!CryptEncrypt(hKey, 0, TRUE, 0, encrypted.data(), &dataLen, bufferLen)) {
                throw std::runtime_error("AES encryption failed");
            }

            encrypted.resize(dataLen);

        } catch (...) {
            if (hKey) CryptDestroyKey(hKey);
            if (hProv) CryptReleaseContext(hProv, 0);
            throw;
        }

        if (hKey) CryptDestroyKey(hKey);
        if (hProv) CryptReleaseContext(hProv, 0);
        return encrypted;
    }

    std::vector<uint8_t> aesDecrypt(const std::vector<uint8_t>& encrypted) {
        HCRYPTPROV hProv = 0;
        HCRYPTKEY hKey = 0;
        std::vector<uint8_t> decrypted;

        try {
            // Acquire crypto context
            if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                throw std::runtime_error("Failed to acquire crypto context");
            }

            // Create key blob
            struct {
                BLOBHEADER hdr;
                DWORD keySize;
                BYTE keyData[32];
            } keyBlob;

            keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
            keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
            keyBlob.hdr.reserved = 0;
            keyBlob.hdr.aiKeyAlg = CALG_AES_256;
            keyBlob.keySize = 32;
            memcpy(keyBlob.keyData, key.data(), 32);

            // Import key
            if (!CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
                throw std::runtime_error("Failed to import AES key");
            }

            // Set IV
            if (!CryptSetKeyParam(hKey, KP_IV, iv.data(), 0)) {
                throw std::runtime_error("Failed to set IV");
            }

            // Decrypt
            decrypted = encrypted;
            DWORD dataLen = static_cast<DWORD>(decrypted.size());
            if (!CryptDecrypt(hKey, 0, TRUE, 0, decrypted.data(), &dataLen)) {
                throw std::runtime_error("AES decryption failed");
            }

            decrypted.resize(dataLen);

        } catch (...) {
            if (hKey) CryptDestroyKey(hKey);
            if (hProv) CryptReleaseContext(hProv, 0);
            throw;
        }

        if (hKey) CryptDestroyKey(hKey);
        if (hProv) CryptReleaseContext(hProv, 0);
        return decrypted;
    }

    // ChaCha20 Encryption (Custom implementation)
    std::vector<uint8_t> chacha20Encrypt(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> encrypted;
        encrypted.reserve(data.size());

        ChaCha20Context ctx;
        chacha20Init(&ctx, key.data(), iv.data());

        // Encrypt in 64-byte blocks
        for (size_t i = 0; i < data.size(); i += 64) {
            uint8_t keystream[64];
            chacha20Block(&ctx, keystream);

            size_t blockSize = std::min(size_t(64), data.size() - i);
            for (size_t j = 0; j < blockSize; ++j) {
                encrypted.push_back(data[i + j] ^ keystream[j]);
            }
            ctx.counter++;
        }

        return encrypted;
    }

    std::vector<uint8_t> chacha20Decrypt(const std::vector<uint8_t>& encrypted) {
        return chacha20Encrypt(encrypted); // ChaCha20 is symmetric
    }

    // Main encrypt function
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, Method method) {
        switch (method) {
            case Method::XOR:
                return xorEncrypt(data);
            case Method::AES:
                return aesEncrypt(data);
            case Method::CHACHA20:
                return chacha20Encrypt(data);
            default:
                return data;
        }
    }

    // Main decrypt function
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& encrypted, Method method) {
        switch (method) {
            case Method::XOR:
                return xorDecrypt(encrypted);
            case Method::AES:
                return aesDecrypt(encrypted);
            case Method::CHACHA20:
                return chacha20Decrypt(encrypted);
            default:
                return encrypted;
        }
    }

    // Get encryption key as hex string
    std::string getKeyHex() const {
        std::string hex;
        for (uint8_t byte : key) {
            char buf[3];
            sprintf_s(buf, "%02X", byte);
            hex += buf;
        }
        return hex;
    }

    // Get IV as hex string
    std::string getIVHex() const {
        std::string hex;
        for (uint8_t byte : iv) {
            char buf[3];
            sprintf_s(buf, "%02X", byte);
            hex += buf;
        }
        return hex;
    }

    // Set key from hex string
    void setKeyFromHex(const std::string& hexKey) {
        key.clear();
        for (size_t i = 0; i < hexKey.length() && i < 64; i += 2) {
            std::string byteStr = hexKey.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(strtoul(byteStr.c_str(), nullptr, 16));
            key.push_back(byte);
        }
        if (key.size() < 32) key.resize(32, 0);
    }

    // Set IV from hex string
    void setIVFromHex(const std::string& hexIV) {
        iv.clear();
        for (size_t i = 0; i < hexIV.length() && i < 32; i += 2) {
            std::string byteStr = hexIV.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(strtoul(byteStr.c_str(), nullptr, 16));
            iv.push_back(byte);
        }
        if (iv.size() < 16) iv.resize(16, 0);
    }

private:
    // ChaCha20 implementation
    struct ChaCha20Context {
        uint32_t state[16];
        uint32_t counter;
    };

    void chacha20Init(ChaCha20Context* ctx, const uint8_t* key, const uint8_t* nonce) {
        // ChaCha20 constants
        ctx->state[0] = 0x61707865;
        ctx->state[1] = 0x3320646e;
        ctx->state[2] = 0x79622d32;
        ctx->state[3] = 0x6b206574;

        // Key (256-bit)
        for (int i = 0; i < 8; ++i) {
            ctx->state[4 + i] = 
                static_cast<uint32_t>(key[i * 4]) |
                (static_cast<uint32_t>(key[i * 4 + 1]) << 8) |
                (static_cast<uint32_t>(key[i * 4 + 2]) << 16) |
                (static_cast<uint32_t>(key[i * 4 + 3]) << 24);
        }

        // Counter
        ctx->counter = 0;
        ctx->state[12] = 0;

        // Nonce (96-bit)
        for (int i = 0; i < 3; ++i) {
            ctx->state[13 + i] = 
                static_cast<uint32_t>(nonce[i * 4]) |
                (static_cast<uint32_t>(nonce[i * 4 + 1]) << 8) |
                (static_cast<uint32_t>(nonce[i * 4 + 2]) << 16) |
                (static_cast<uint32_t>(nonce[i * 4 + 3]) << 24);
        }
    }

    uint32_t rotateLeft(uint32_t value, int shift) {
        return (value << shift) | (value >> (32 - shift));
    }

    void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = rotateLeft(d, 16);
        c += d; b ^= c; b = rotateLeft(b, 12);
        a += b; d ^= a; d = rotateLeft(d, 8);
        c += d; b ^= c; b = rotateLeft(b, 7);
    }

    void chacha20Block(ChaCha20Context* ctx, uint8_t* output) {
        uint32_t working[16];
        
        // Copy state
        for (int i = 0; i < 16; ++i) {
            working[i] = ctx->state[i];
        }
        working[12] = ctx->counter;

        // 20 rounds (10 double rounds)
        for (int i = 0; i < 10; ++i) {
            // Column rounds
            quarterRound(working[0], working[4], working[8], working[12]);
            quarterRound(working[1], working[5], working[9], working[13]);
            quarterRound(working[2], working[6], working[10], working[14]);
            quarterRound(working[3], working[7], working[11], working[15]);

            // Diagonal rounds
            quarterRound(working[0], working[5], working[10], working[15]);
            quarterRound(working[1], working[6], working[11], working[12]);
            quarterRound(working[2], working[7], working[8], working[13]);
            quarterRound(working[3], working[4], working[9], working[14]);
        }

        // Add original state
        for (int i = 0; i < 16; ++i) {
            if (i == 12) {
                working[i] += ctx->counter;
            } else {
                working[i] += ctx->state[i];
            }
        }

        // Convert to bytes
        for (int i = 0; i < 16; ++i) {
            output[i * 4 + 0] = working[i] & 0xFF;
            output[i * 4 + 1] = (working[i] >> 8) & 0xFF;
            output[i * 4 + 2] = (working[i] >> 16) & 0xFF;
            output[i * 4 + 3] = (working[i] >> 24) & 0xFF;
        }
    }
};
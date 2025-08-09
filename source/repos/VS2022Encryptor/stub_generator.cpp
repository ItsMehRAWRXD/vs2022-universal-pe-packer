#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <ctime>
#include <iomanip>
#include <sstream>

class StubGenerator {
private:
    std::mt19937 rng;
    
    struct StubConfig {
        std::string name;
        int encryption_layers;
        bool anti_debug;
        bool header_obfuscation;
        bool timing_checks;
        bool dummy_sections;
        int padding_size;
        std::string encryption_key;
        bool compress_data;
        bool fake_imports;
    };

public:
    StubGenerator() : rng(std::time(nullptr)) {}
    
    std::vector<unsigned char> createBasicPEStub(const StubConfig& config) {
        std::vector<unsigned char> stub;
        
        // DOS Header
        stub.insert(stub.end(), {'M', 'Z'});  // e_magic
        
        // DOS header padding (58 bytes)
        for (int i = 0; i < 58; ++i) {
            stub.push_back(config.dummy_sections ? getRandomByte() : 0x00);
        }
        
        // PE header offset (at position 60)
        uint32_t peOffset = 128 + config.padding_size;
        stub.push_back(peOffset & 0xFF);
        stub.push_back((peOffset >> 8) & 0xFF);
        stub.push_back((peOffset >> 16) & 0xFF);
        stub.push_back((peOffset >> 24) & 0xFF);
        
        // DOS stub program (variable size based on config)
        int dosStubSize = 64 + config.padding_size;
        for (int i = 0; i < dosStubSize; ++i) {
            if (config.anti_debug && i % 16 == 0) {
                // Add anti-debug markers
                stub.push_back(0xCD);  // INT instruction
            } else {
                stub.push_back(config.dummy_sections ? getRandomByte() : 0x90); // NOP or random
            }
        }
        
        // PE Signature
        stub.insert(stub.end(), {'P', 'E', 0x00, 0x00});
        
        // COFF Header
        stub.insert(stub.end(), {0x4C, 0x01}); // Machine (i386)
        
        uint16_t numberOfSections = config.dummy_sections ? 4 : 2;
        stub.push_back(numberOfSections & 0xFF);
        stub.push_back((numberOfSections >> 8) & 0xFF);
        
        // Timestamp (obfuscated if enabled)
        uint32_t timestamp = config.header_obfuscation ? getRandomDword() : std::time(nullptr);
        addDword(stub, timestamp);
        
        // PointerToSymbolTable, NumberOfSymbols
        addDword(stub, 0);
        addDword(stub, 0);
        
        // SizeOfOptionalHeader
        uint16_t optHeaderSize = 224 + (config.fake_imports ? 64 : 0);
        stub.push_back(optHeaderSize & 0xFF);
        stub.push_back((optHeaderSize >> 8) & 0xFF);
        
        // Characteristics
        uint16_t characteristics = 0x0102; // EXECUTABLE_IMAGE | 32BIT_MACHINE
        if (config.anti_debug) characteristics |= 0x2000; // DLL flag as obfuscation
        addWord(stub, characteristics);
        
        // Optional Header
        addOptionalHeader(stub, config);
        
        // Section Headers
        addSectionHeaders(stub, config);
        
        // Section Data
        addSectionData(stub, config);
        
        return stub;
    }
    
private:
    unsigned char getRandomByte() {
        return static_cast<unsigned char>(rng() % 256);
    }
    
    uint32_t getRandomDword() {
        return rng();
    }
    
    void addWord(std::vector<unsigned char>& data, uint16_t value) {
        data.push_back(value & 0xFF);
        data.push_back((value >> 8) & 0xFF);
    }
    
    void addDword(std::vector<unsigned char>& data, uint32_t value) {
        data.push_back(value & 0xFF);
        data.push_back((value >> 8) & 0xFF);
        data.push_back((value >> 16) & 0xFF);
        data.push_back((value >> 24) & 0xFF);
    }
    
    void addOptionalHeader(std::vector<unsigned char>& stub, const StubConfig& config) {
        // Magic (PE32)
        addWord(stub, 0x10B);
        
        // Linker version
        stub.push_back(14); // Major
        stub.push_back(config.header_obfuscation ? getRandomByte() : 0); // Minor
        
        // Size of Code, Initialized Data, Uninitialized Data
        addDword(stub, 0x1000);
        addDword(stub, 0x1000);
        addDword(stub, 0);
        
        // Entry Point (obfuscated if enabled)
        uint32_t entryPoint = config.header_obfuscation ? 0x1000 + (rng() % 0x100) : 0x1000;
        addDword(stub, entryPoint);
        
        // Base of Code, Base of Data
        addDword(stub, 0x1000);
        addDword(stub, 0x2000);
        
        // Image Base
        addDword(stub, 0x400000);
        
        // Section Alignment, File Alignment
        addDword(stub, 0x1000);
        addDword(stub, 0x200);
        
        // OS Version, Image Version, Subsystem Version
        addWord(stub, 6); // Major OS
        addWord(stub, 0); // Minor OS
        addWord(stub, 0); // Major Image
        addWord(stub, 0); // Minor Image
        addWord(stub, 6); // Major Subsystem
        addWord(stub, 0); // Minor Subsystem
        
        // Reserved
        addDword(stub, 0);
        
        // Size of Image, Size of Headers
        uint32_t imageSize = 0x3000 + (config.dummy_sections ? 0x2000 : 0);
        addDword(stub, imageSize);
        addDword(stub, 0x400);
        
        // Checksum (randomized if obfuscation enabled)
        addDword(stub, config.header_obfuscation ? getRandomDword() : 0);
        
        // Subsystem (Console)
        addWord(stub, 3);
        
        // DLL Characteristics
        uint16_t dllChar = config.anti_debug ? 0x8000 : 0x0000; // ASLR flag
        addWord(stub, dllChar);
        
        // Stack Reserve, Stack Commit, Heap Reserve, Heap Commit
        addDword(stub, 0x100000);
        addDword(stub, 0x1000);
        addDword(stub, 0x100000);
        addDword(stub, 0x1000);
        
        // Loader Flags
        addDword(stub, 0);
        
        // Number of RVA and Sizes
        addDword(stub, 16);
        
        // Data Directories (16 entries)
        for (int i = 0; i < 16; ++i) {
            if (i == 1 && config.fake_imports) {
                // Import Table
                addDword(stub, 0x2000);
                addDword(stub, 0x100);
            } else {
                addDword(stub, 0);
                addDword(stub, 0);
            }
        }
    }
    
    void addSectionHeaders(std::vector<unsigned char>& stub, const StubConfig& config) {
        // .text section
        addSectionHeader(stub, ".text", 0x1000, 0x1000, 0x400, 0x60000020);
        
        // .data section  
        addSectionHeader(stub, ".data", 0x2000, 0x1000, 0x600, 0xC0000040);
        
        if (config.dummy_sections) {
            // .rsrc section (dummy)
            addSectionHeader(stub, ".rsrc", 0x3000, 0x1000, 0x800, 0x40000040);
            
            // .reloc section (dummy)
            addSectionHeader(stub, ".reloc", 0x4000, 0x1000, 0xA00, 0x42000040);
        }
    }
    
    void addSectionHeader(std::vector<unsigned char>& stub, const std::string& name, 
                         uint32_t virtualAddr, uint32_t virtualSize, 
                         uint32_t rawAddr, uint32_t characteristics) {
        // Name (8 bytes, null-padded)
        for (int i = 0; i < 8; ++i) {
            stub.push_back(i < name.length() ? name[i] : 0);
        }
        
        addDword(stub, virtualSize);  // VirtualSize
        addDword(stub, virtualAddr);  // VirtualAddress
        addDword(stub, virtualSize);  // SizeOfRawData
        addDword(stub, rawAddr);      // PointerToRawData
        addDword(stub, 0);            // PointerToRelocations
        addDword(stub, 0);            // PointerToLinenumbers
        addWord(stub, 0);             // NumberOfRelocations
        addWord(stub, 0);             // NumberOfLinenumbers
        addDword(stub, characteristics); // Characteristics
    }
    
    void addSectionData(std::vector<unsigned char>& stub, const StubConfig& config) {
        // Pad to first section
        while (stub.size() < 0x400) {
            stub.push_back(0);
        }
        
        // .text section data
        addTextSection(stub, config);
        
        // Pad to .data section
        while (stub.size() < 0x600) {
            stub.push_back(0);
        }
        
        // .data section
        addDataSection(stub, config);
        
        if (config.dummy_sections) {
            // Pad and add dummy sections
            while (stub.size() < 0x800) {
                stub.push_back(0);
            }
            addDummySection(stub, 0x1000); // .rsrc
            
            while (stub.size() < 0xA00) {
                stub.push_back(0);
            }
            addDummySection(stub, 0x1000); // .reloc
        }
    }
    
    void addTextSection(std::vector<unsigned char>& stub, const StubConfig& config) {
        if (config.timing_checks) {
            // Add timing check code
            stub.insert(stub.end(), {0xE8, 0x00, 0x00, 0x00, 0x00}); // CALL GetTickCount
            stub.insert(stub.end(), {0x50}); // PUSH EAX
        }
        
        // Simple payload: print message and exit
        std::vector<unsigned char> payload = {
            0x68, 0x00, 0x20, 0x40, 0x00,  // PUSH message_addr
            0xE8, 0x00, 0x00, 0x00, 0x00,  // CALL printf
            0x6A, 0x00,                     // PUSH 0
            0xE8, 0x00, 0x00, 0x00, 0x00,  // CALL exit
        };
        
        stub.insert(stub.end(), payload.begin(), payload.end());
        
        // Pad with NOPs or anti-debug instructions
        while (stub.size() % 0x200 != 0 && stub.size() < 0x600) {
            if (config.anti_debug && (stub.size() % 32) == 0) {
                stub.push_back(0xCD); // INT (anti-debug)
                stub.push_back(0x03);
            } else {
                stub.push_back(0x90); // NOP
            }
        }
    }
    
    void addDataSection(std::vector<unsigned char>& stub, const StubConfig& config) {
        // Add encrypted payload marker
        std::string message = "Stub " + config.name + " Active!";
        
        if (config.encryption_layers > 0) {
            // Simple XOR encryption
            for (char& c : message) {
                for (int layer = 0; layer < config.encryption_layers; ++layer) {
                    c ^= config.encryption_key[layer % config.encryption_key.length()];
                }
            }
        }
        
        for (char c : message) {
            stub.push_back(static_cast<unsigned char>(c));
        }
        stub.push_back(0); // Null terminator
        
        // Pad section
        while (stub.size() % 0x200 != 0 && stub.size() < 0x800) {
            stub.push_back(config.dummy_sections ? getRandomByte() : 0);
        }
    }
    
    void addDummySection(std::vector<unsigned char>& stub, size_t size) {
        for (size_t i = 0; i < size; ++i) {
            stub.push_back(getRandomByte());
        }
    }

public:
    void generateAllStubs() {
        std::vector<StubConfig> configs = {
            {"Basic", 1, false, false, false, false, 0, "key1", false, false},
            {"AntiDebug", 1, true, false, false, false, 0, "key2", false, false},
            {"Obfuscated", 1, false, true, false, false, 0, "key3", false, false},
            {"Timing", 1, false, false, true, false, 0, "key4", false, false},
            {"DummySections", 1, false, false, false, true, 0, "key5", false, false},
            {"Padded", 1, false, false, false, false, 512, "key6", false, false},
            {"DoubleEncrypt", 2, false, false, false, false, 0, "key7", false, false},
            {"TripleEncrypt", 3, false, false, false, false, 0, "key8", false, false},
            {"MaxEncrypt", 5, false, false, false, false, 0, "key9", false, false},
            {"FakeImports", 1, false, false, false, false, 0, "key10", false, true},
            {"Compressed", 1, false, false, false, false, 0, "key11", true, false},
            {"AntiDebugObfus", 2, true, true, false, false, 0, "key12", false, false},
            {"TimingPadded", 1, false, false, true, false, 256, "key13", false, false},
            {"DummyAntiDebug", 1, true, false, false, true, 0, "key14", false, false},
            {"FullObfuscation", 2, true, true, true, false, 128, "key15", false, false},
            {"MaxFeatures", 3, true, true, true, true, 256, "key16", true, true},
            {"LargePadding", 1, false, false, false, false, 1024, "key17", false, false},
            {"MegaEncrypt", 7, false, false, false, false, 0, "key18", false, false},
            {"StealthMax", 4, true, true, true, true, 512, "key19", true, false},
            {"MinimalStealth", 1, true, false, false, false, 64, "key20", false, false},
            {"RandomObfus", 2, false, true, false, true, 384, "key21", false, true},
            {"TimingMax", 3, false, false, true, false, 768, "key22", true, false},
            {"ImportHeavy", 1, false, false, false, false, 0, "key23", false, true},
            {"BalancedAll", 2, true, true, false, true, 192, "key24", true, true},
            {"Ultimate", 5, true, true, true, true, 1024, "key25", true, true}
        };
        
        std::cout << "Generating 25 different PE stubs...\n" << std::endl;
        
        for (size_t i = 0; i < configs.size(); ++i) {
            std::cout << "Generating stub " << (i+1) << ": " << configs[i].name << std::endl;
            
            auto stubData = createBasicPEStub(configs[i]);
            
            std::stringstream filename;
            filename << "stub_" << std::setfill('0') << std::setw(2) << (i+1) 
                    << "_" << configs[i].name << ".exe";
            
            std::ofstream file(filename.str(), std::ios::binary);
            file.write(reinterpret_cast<const char*>(stubData.data()), stubData.size());
            file.close();
            
            std::cout << "  - Size: " << stubData.size() << " bytes" << std::endl;
            std::cout << "  - Features: ";
            if (configs[i].anti_debug) std::cout << "AntiDebug ";
            if (configs[i].header_obfuscation) std::cout << "HeaderObfus ";
            if (configs[i].timing_checks) std::cout << "Timing ";
            if (configs[i].dummy_sections) std::cout << "DummySections ";
            if (configs[i].fake_imports) std::cout << "FakeImports ";
            if (configs[i].compress_data) std::cout << "Compression ";
            std::cout << std::endl;
            std::cout << "  - Encryption layers: " << configs[i].encryption_layers << std::endl;
            std::cout << "  - Padding: " << configs[i].padding_size << " bytes" << std::endl;
            std::cout << std::endl;
        }
        
        std::cout << "All 25 stubs generated successfully!" << std::endl;
    }
};

int main() {
    std::cout << "PE Stub Generator - Creating 25 Variants\n";
    std::cout << "========================================\n" << std::endl;
    
    StubGenerator generator;
    generator.generateAllStubs();
    
    return 0;
}
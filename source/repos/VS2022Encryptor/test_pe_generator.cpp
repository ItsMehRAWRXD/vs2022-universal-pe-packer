#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <ctime>

class TestPEGenerator {
private:
    std::mt19937 rng;

public:
    TestPEGenerator() : rng(std::time(nullptr)) {}

    std::vector<unsigned char> createBasicPE(const std::string& name) {
        std::vector<unsigned char> pe;
        
        // DOS Header
        pe.insert(pe.end(), {'M', 'Z'}); // e_magic
        
        // DOS header padding (58 bytes)
        for (int i = 0; i < 58; ++i) {
            pe.push_back(0x00);
        }
        
        // PE header offset (at position 60)
        addDword(pe, 0x80); // PE at offset 128
        
        // DOS stub program (64 bytes)
        for (int i = 0; i < 64; ++i) {
            pe.push_back(0x90); // NOP
        }
        
        // PE Signature
        pe.insert(pe.end(), {'P', 'E', 0x00, 0x00});
        
        // COFF Header
        addWord(pe, 0x014C); // Machine (i386)
        addWord(pe, 2);      // Number of sections
        addDword(pe, std::time(nullptr)); // Timestamp
        addDword(pe, 0);     // PointerToSymbolTable
        addDword(pe, 0);     // NumberOfSymbols
        addWord(pe, 224);    // SizeOfOptionalHeader
        addWord(pe, 0x0102); // Characteristics
        
        // Optional Header
        addOptionalHeader(pe, name);
        
        // Section Headers
        addSectionHeader(pe, ".text", 0x1000, 0x1000, 0x400, 0x60000020);
        addSectionHeader(pe, ".data", 0x2000, 0x1000, 0x600, 0xC0000040);
        
        // Pad to first section
        while (pe.size() < 0x400) {
            pe.push_back(0);
        }
        
        // .text section (simple payload)
        addTextSection(pe, name);
        
        // Pad to .data section  
        while (pe.size() < 0x600) {
            pe.push_back(0);
        }
        
        // .data section
        addDataSection(pe, name);
        
        return pe;
    }
    
    std::vector<unsigned char> createComplexPE(const std::string& name) {
        std::vector<unsigned char> pe;
        
        // DOS Header with more realistic content
        pe.insert(pe.end(), {'M', 'Z'}); // e_magic
        addWord(pe, 0x90);   // e_cblp
        addWord(pe, 0x03);   // e_cp
        addWord(pe, 0x00);   // e_crlc
        addWord(pe, 0x04);   // e_cparhdr
        addWord(pe, 0x00);   // e_minalloc
        addWord(pe, 0xFFFF); // e_maxalloc
        addWord(pe, 0x00);   // e_ss
        addWord(pe, 0xB8);   // e_sp
        addWord(pe, 0x00);   // e_csum
        addWord(pe, 0x00);   // e_ip
        addWord(pe, 0x00);   // e_cs
        addWord(pe, 0x40);   // e_lfarlc
        addWord(pe, 0x00);   // e_ovno
        
        // Reserved words
        for (int i = 0; i < 4; ++i) {
            addWord(pe, 0);
        }
        
        addWord(pe, 0x00);   // e_oemid
        addWord(pe, 0x00);   // e_oeminfo
        
        // Reserved words
        for (int i = 0; i < 10; ++i) {
            addWord(pe, 0);
        }
        
        addDword(pe, 0xE0); // PE header offset
        
        // DOS stub with actual code
        std::vector<unsigned char> dosStub = {
            0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD,
            0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
            0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72,
            0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
            0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E,
            0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
            0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
            0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        
        pe.insert(pe.end(), dosStub.begin(), dosStub.end());
        
        // Pad to PE header
        while (pe.size() < 0xE0) {
            pe.push_back(0);
        }
        
        // PE Signature
        pe.insert(pe.end(), {'P', 'E', 0x00, 0x00});
        
        // COFF Header
        addWord(pe, 0x014C); // Machine (i386)
        addWord(pe, 4);      // Number of sections
        addDword(pe, std::time(nullptr)); // Timestamp
        addDword(pe, 0);     // PointerToSymbolTable
        addDword(pe, 0);     // NumberOfSymbols
        addWord(pe, 224);    // SizeOfOptionalHeader
        addWord(pe, 0x0102); // Characteristics
        
        // Optional Header
        addComplexOptionalHeader(pe, name);
        
        // Section Headers
        addSectionHeader(pe, ".text", 0x1000, 0x2000, 0x400, 0x60000020);
        addSectionHeader(pe, ".rdata", 0x3000, 0x1000, 0x2400, 0x40000040);
        addSectionHeader(pe, ".data", 0x4000, 0x1000, 0x3400, 0xC0000040);
        addSectionHeader(pe, ".rsrc", 0x5000, 0x1000, 0x4400, 0x40000040);
        
        // Pad to first section
        while (pe.size() < 0x400) {
            pe.push_back(0);
        }
        
        // Complex sections with realistic content
        addComplexTextSection(pe, name);
        addComplexReadOnlyDataSection(pe, name);
        addComplexDataSection(pe, name);
        addResourceSection(pe, name);
        
        return pe;
    }

private:
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
    
    void addOptionalHeader(std::vector<unsigned char>& pe, const std::string& name) {
        addWord(pe, 0x10B);    // Magic (PE32)
        pe.push_back(14);      // MajorLinkerVersion
        pe.push_back(0);       // MinorLinkerVersion
        addDword(pe, 0x1000);  // SizeOfCode
        addDword(pe, 0x1000);  // SizeOfInitializedData
        addDword(pe, 0);       // SizeOfUninitializedData
        addDword(pe, 0x1000);  // AddressOfEntryPoint
        addDword(pe, 0x1000);  // BaseOfCode
        addDword(pe, 0x2000);  // BaseOfData
        addDword(pe, 0x400000); // ImageBase
        addDword(pe, 0x1000);  // SectionAlignment
        addDword(pe, 0x200);   // FileAlignment
        addWord(pe, 6);        // MajorOSVersion
        addWord(pe, 0);        // MinorOSVersion
        addWord(pe, 0);        // MajorImageVersion
        addWord(pe, 0);        // MinorImageVersion
        addWord(pe, 6);        // MajorSubsystemVersion
        addWord(pe, 0);        // MinorSubsystemVersion
        addDword(pe, 0);       // Win32VersionValue
        addDword(pe, 0x3000);  // SizeOfImage
        addDword(pe, 0x400);   // SizeOfHeaders
        addDword(pe, 0);       // CheckSum
        addWord(pe, 3);        // Subsystem (Console)
        addWord(pe, 0);        // DllCharacteristics
        addDword(pe, 0x100000); // SizeOfStackReserve
        addDword(pe, 0x1000);  // SizeOfStackCommit
        addDword(pe, 0x100000); // SizeOfHeapReserve
        addDword(pe, 0x1000);  // SizeOfHeapCommit
        addDword(pe, 0);       // LoaderFlags
        addDword(pe, 16);      // NumberOfRvaAndSizes
        
        // Data Directories (16 entries)
        for (int i = 0; i < 16; ++i) {
            addDword(pe, 0);
            addDword(pe, 0);
        }
    }
    
    void addComplexOptionalHeader(std::vector<unsigned char>& pe, const std::string& name) {
        addWord(pe, 0x10B);    // Magic (PE32)
        pe.push_back(14);      // MajorLinkerVersion
        pe.push_back(0);       // MinorLinkerVersion
        addDword(pe, 0x2000);  // SizeOfCode
        addDword(pe, 0x2000);  // SizeOfInitializedData
        addDword(pe, 0);       // SizeOfUninitializedData
        addDword(pe, 0x1050);  // AddressOfEntryPoint
        addDword(pe, 0x1000);  // BaseOfCode
        addDword(pe, 0x3000);  // BaseOfData
        addDword(pe, 0x400000); // ImageBase
        addDword(pe, 0x1000);  // SectionAlignment
        addDword(pe, 0x200);   // FileAlignment
        addWord(pe, 6);        // MajorOSVersion
        addWord(pe, 0);        // MinorOSVersion
        addWord(pe, 1);        // MajorImageVersion
        addWord(pe, 0);        // MinorImageVersion
        addWord(pe, 6);        // MajorSubsystemVersion
        addWord(pe, 0);        // MinorSubsystemVersion
        addDword(pe, 0);       // Win32VersionValue
        addDword(pe, 0x6000);  // SizeOfImage
        addDword(pe, 0x400);   // SizeOfHeaders
        addDword(pe, 0);       // CheckSum
        addWord(pe, 3);        // Subsystem (Console)
        addWord(pe, 0x8000);   // DllCharacteristics (ASLR)
        addDword(pe, 0x100000); // SizeOfStackReserve
        addDword(pe, 0x1000);  // SizeOfStackCommit
        addDword(pe, 0x100000); // SizeOfHeapReserve
        addDword(pe, 0x1000);  // SizeOfHeapCommit
        addDword(pe, 0);       // LoaderFlags
        addDword(pe, 16);      // NumberOfRvaAndSizes
        
        // Data Directories
        for (int i = 0; i < 16; ++i) {
            if (i == 1) { // Import Table
                addDword(pe, 0x3000);
                addDword(pe, 0x100);
            } else if (i == 2) { // Resource Table
                addDword(pe, 0x5000);
                addDword(pe, 0x1000);
            } else {
                addDword(pe, 0);
                addDword(pe, 0);
            }
        }
    }
    
    void addSectionHeader(std::vector<unsigned char>& pe, const std::string& name, 
                         uint32_t virtualAddr, uint32_t virtualSize, 
                         uint32_t rawAddr, uint32_t characteristics) {
        // Name (8 bytes)
        for (int i = 0; i < 8; ++i) {
            pe.push_back(i < name.length() ? name[i] : 0);
        }
        
        addDword(pe, virtualSize);
        addDword(pe, virtualAddr);
        addDword(pe, virtualSize);
        addDword(pe, rawAddr);
        addDword(pe, 0); // PointerToRelocations
        addDword(pe, 0); // PointerToLinenumbers
        addWord(pe, 0);  // NumberOfRelocations
        addWord(pe, 0);  // NumberOfLinenumbers
        addDword(pe, characteristics);
    }
    
    void addTextSection(std::vector<unsigned char>& pe, const std::string& name) {
        // Simple message and exit
        std::vector<unsigned char> code = {
            0x68, 0x00, 0x20, 0x40, 0x00, // PUSH message_addr
            0xE8, 0x00, 0x00, 0x00, 0x00, // CALL printf
            0x6A, 0x00,                   // PUSH 0
            0xE8, 0x00, 0x00, 0x00, 0x00, // CALL exit
        };
        
        pe.insert(pe.end(), code.begin(), code.end());
        
        // Pad section
        while (pe.size() % 0x200 != 0 && pe.size() < 0x600) {
            pe.push_back(0x90); // NOP
        }
    }
    
    void addComplexTextSection(std::vector<unsigned char>& pe, const std::string& name) {
        // More realistic x86 code
        std::vector<unsigned char> code = {
            // Function prologue
            0x55,                         // PUSH EBP
            0x8B, 0xEC,                   // MOV EBP, ESP
            0x83, 0xEC, 0x10,             // SUB ESP, 16
            
            // Function body
            0x68, 0x00, 0x30, 0x40, 0x00, // PUSH string_addr
            0xE8, 0x00, 0x00, 0x00, 0x00, // CALL printf
            0x83, 0xC4, 0x04,             // ADD ESP, 4
            
            // Return value
            0x33, 0xC0,                   // XOR EAX, EAX
            
            // Function epilogue
            0x8B, 0xE5,                   // MOV ESP, EBP
            0x5D,                         // POP EBP
            0xC3,                         // RET
            
            // Additional functions
            0x90, 0x90, 0x90, 0x90,       // NOPs for alignment
        };
        
        pe.insert(pe.end(), code.begin(), code.end());
        
        // Add more realistic code patterns
        for (int i = 0; i < 100; ++i) {
            switch (i % 4) {
                case 0:
                    pe.insert(pe.end(), {0x50, 0x58}); // PUSH EAX, POP EAX
                    break;
                case 1:
                    pe.insert(pe.end(), {0x40, 0x48}); // INC EAX, DEC EAX
                    break;
                case 2:
                    pe.insert(pe.end(), {0x90, 0x90}); // NOP, NOP
                    break;
                case 3:
                    pe.insert(pe.end(), {0x33, 0xC0}); // XOR EAX, EAX
                    break;
            }
        }
        
        // Pad to section boundary
        while (pe.size() % 0x200 != 0) {
            pe.push_back(0x90);
        }
    }
    
    void addDataSection(std::vector<unsigned char>& pe, const std::string& name) {
        std::string message = "Test PE: " + name;
        for (char c : message) {
            pe.push_back(static_cast<unsigned char>(c));
        }
        pe.push_back(0); // Null terminator
        
        // Pad section
        while (pe.size() % 0x200 != 0) {
            pe.push_back(0);
        }
    }
    
    void addComplexReadOnlyDataSection(std::vector<unsigned char>& pe, const std::string& name) {
        while (pe.size() < 0x2400) {
            pe.push_back(0);
        }
        
        // Import table data
        std::vector<std::string> imports = {"kernel32.dll", "user32.dll", "msvcrt.dll"};
        for (const auto& dll : imports) {
            for (char c : dll) {
                pe.push_back(static_cast<unsigned char>(c));
            }
            pe.push_back(0);
        }
        
        // Pad section
        while (pe.size() % 0x200 != 0) {
            pe.push_back(0);
        }
    }
    
    void addComplexDataSection(std::vector<unsigned char>& pe, const std::string& name) {
        while (pe.size() < 0x3400) {
            pe.push_back(0);
        }
        
        // Global variables
        std::string message = "Complex Test PE: " + name + " with global data";
        for (char c : message) {
            pe.push_back(static_cast<unsigned char>(c));
        }
        pe.push_back(0);
        
        // Some initialized data
        addDword(pe, 0x12345678);
        addDword(pe, 0x87654321);
        addDword(pe, 0xDEADBEEF);
        addDword(pe, 0xCAFEBABE);
        
        // Pad section
        while (pe.size() % 0x200 != 0) {
            pe.push_back(0);
        }
    }
    
    void addResourceSection(std::vector<unsigned char>& pe, const std::string& name) {
        while (pe.size() < 0x4400) {
            pe.push_back(0);
        }
        
        // Fake resource data
        std::string resData = "RESOURCE_DATA_" + name;
        for (char c : resData) {
            pe.push_back(static_cast<unsigned char>(c));
        }
        
        // Fill with pattern
        for (int i = 0; i < 500; ++i) {
            pe.push_back(static_cast<unsigned char>(i % 256));
        }
        
        // Pad section
        while (pe.size() % 0x200 != 0) {
            pe.push_back(0);
        }
    }

public:
    void generateTestPEs() {
        std::cout << "Generating test PE files...\n" << std::endl;
        
        // Basic PEs
        for (int i = 1; i <= 5; ++i) {
            std::string name = "BasicTest" + std::to_string(i);
            auto peData = createBasicPE(name);
            
            std::string filename = "test_pe_basic_" + std::to_string(i) + ".exe";
            std::ofstream file(filename, std::ios::binary);
            file.write(reinterpret_cast<const char*>(peData.data()), peData.size());
            file.close();
            
            std::cout << "Created " << filename << " (" << peData.size() << " bytes)" << std::endl;
        }
        
        // Complex PEs
        for (int i = 1; i <= 5; ++i) {
            std::string name = "ComplexTest" + std::to_string(i);
            auto peData = createComplexPE(name);
            
            std::string filename = "test_pe_complex_" + std::to_string(i) + ".exe";
            std::ofstream file(filename, std::ios::binary);
            file.write(reinterpret_cast<const char*>(peData.data()), peData.size());
            file.close();
            
            std::cout << "Created " << filename << " (" << peData.size() << " bytes)" << std::endl;
        }
        
        std::cout << "\nAll test PE files generated successfully!" << std::endl;
    }
};

int main() {
    std::cout << "Test PE Generator - Creating Test Files\n";
    std::cout << "======================================\n" << std::endl;
    
    TestPEGenerator generator;
    generator.generateTestPEs();
    
    return 0;
}
#include <windows.h>
#include <vector>
#include <string>
#include <map>
#include <regex>
#include <sstream>
#include <algorithm>

class InternalCompiler {
private:
    std::map<std::string, std::vector<uint8_t>> functionTemplates;
    std::map<std::string, uint32_t> stringLiterals;
    std::vector<std::string> imports;
    
public:
    InternalCompiler() {
        initializeFunctionTemplates();
    }
    
    std::vector<uint8_t> compileSourceToExecutable(const std::string& sourceCode) {
        // Parse the source code
        auto parsedCode = parseSourceCode(sourceCode);
        
        // Generate machine code
        auto machineCode = generateMachineCode(parsedCode);
        
        // Create PE executable
        return createPEExecutable(machineCode);
    }
    
private:
    struct ParsedFunction {
        std::string name;
        std::string returnType;
        std::vector<std::string> parameters;
        std::vector<std::string> body;
        bool isMain;
    };
    
    struct ParsedCode {
        std::vector<ParsedFunction> functions;
        std::vector<std::string> includes;
        std::vector<std::string> globalVars;
        std::vector<std::string> stringLiterals;
    };
    
    void initializeFunctionTemplates() {
        // WinMain template
        functionTemplates["WinMain"] = {
            0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x20,      // push ebp; mov ebp, esp; sub esp, 32
            0x68, 0x00, 0x00, 0x00, 0x00,            // push 0 (exit code)
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,      // call ExitProcess
            0x8B, 0xE5, 0x5D, 0xC3                   // mov esp, ebp; pop ebp; ret
        };
        
        // main template
        functionTemplates["main"] = {
            0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08,      // push ebp; mov ebp, esp; sub esp, 8
            0x68, 0x00, 0x00, 0x00, 0x00,            // push 0 (exit code)
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,      // call ExitProcess
            0x8B, 0xE5, 0x5D, 0xC3                   // mov esp, ebp; pop ebp; ret
        };
        
        // MessageBox template
        functionTemplates["MessageBox"] = {
            0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10,      // push ebp; mov ebp, esp; sub esp, 16
            0x68, 0x00, 0x00, 0x00, 0x00,            // push MB_OK
            0x68, 0x00, 0x00, 0x00, 0x00,            // push caption
            0x68, 0x00, 0x00, 0x00, 0x00,            // push text
            0x68, 0x00, 0x00, 0x00, 0x00,            // push hwnd
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,      // call MessageBoxA
            0x8B, 0xE5, 0x5D, 0xC3                   // mov esp, ebp; pop ebp; ret
        };
    }
    
    ParsedCode parseSourceCode(const std::string& sourceCode) {
        ParsedCode parsed;
        
        // Extract includes
        std::regex includeRegex(R"(#include\s*[<"]([^>"]+)[>"])");
        std::sregex_iterator includeIter(sourceCode.begin(), sourceCode.end(), includeRegex);
        std::sregex_iterator includeEnd;
        for (; includeIter != includeEnd; ++includeIter) {
            parsed.includes.push_back((*includeIter)[1]);
        }
        
        // Extract function definitions
        std::regex funcRegex(R"((\w+)\s+(\w+)\s*\([^)]*\)\s*\{)");
        std::sregex_iterator funcIter(sourceCode.begin(), sourceCode.end(), funcRegex);
        std::sregex_iterator funcEnd;
        for (; funcIter != funcEnd; ++funcIter) {
            ParsedFunction func;
            func.returnType = (*funcIter)[1];
            func.name = (*funcIter)[2];
            func.isMain = (func.name == "main" || func.name == "WinMain");
            
            // Extract function body
            size_t startPos = funcIter->suffix().first - sourceCode.begin();
            size_t braceCount = 0;
            bool inBody = false;
            std::string body;
            
            for (size_t i = startPos; i < sourceCode.length(); ++i) {
                char c = sourceCode[i];
                if (c == '{') {
                    if (!inBody) inBody = true;
                    braceCount++;
                } else if (c == '}') {
                    braceCount--;
                    if (braceCount == 0) break;
                }
                if (inBody) body += c;
            }
            
            // Parse body lines
            std::istringstream bodyStream(body);
            std::string line;
            while (std::getline(bodyStream, line)) {
                if (!line.empty()) {
                    func.body.push_back(line);
                }
            }
            
            parsed.functions.push_back(func);
        }
        
        // Extract string literals
        std::regex stringRegex(R"("([^"]*)")");
        std::sregex_iterator stringIter(sourceCode.begin(), sourceCode.end(), stringRegex);
        std::sregex_iterator stringEnd;
        for (; stringIter != stringEnd; ++stringIter) {
            parsed.stringLiterals.push_back((*stringIter)[1]);
        }
        
        return parsed;
    }
    
    std::vector<uint8_t> generateMachineCode(const ParsedCode& parsedCode) {
        std::vector<uint8_t> machineCode;
        
        // Find main function
        auto mainFunc = std::find_if(parsedCode.functions.begin(), parsedCode.functions.end(),
            [](const ParsedFunction& f) { return f.isMain; });
        
        if (mainFunc != parsedCode.functions.end()) {
            // Generate code for main function
            machineCode = generateFunctionCode(*mainFunc, parsedCode);
        } else {
            // Generate default executable
            machineCode = generateDefaultExecutable();
        }
        
        return machineCode;
    }
    
    std::vector<uint8_t> generateFunctionCode(const ParsedFunction& func, const ParsedCode& parsedCode) {
        std::vector<uint8_t> code;
        
        // Function prologue
        code = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x20 };  // push ebp; mov ebp, esp; sub esp, 32
        
        // Process function body
        for (const auto& line : func.body) {
            auto lineCode = compileStatement(line, parsedCode);
            code.insert(code.end(), lineCode.begin(), lineCode.end());
        }
        
        // Function epilogue
        std::vector<uint8_t> epilogue = { 0x8B, 0xE5, 0x5D, 0xC3 };  // mov esp, ebp; pop ebp; ret
        code.insert(code.end(), epilogue.begin(), epilogue.end());
        
        return code;
    }
    
    std::vector<uint8_t> compileStatement(const std::string& statement, const ParsedCode& parsedCode) {
        std::vector<uint8_t> code;
        
        // Remove leading/trailing whitespace
        std::string stmt = statement;
        stmt.erase(0, stmt.find_first_not_of(" \t"));
        stmt.erase(stmt.find_last_not_of(" \t") + 1);
        
        // Handle different statement types
        if (stmt.find("MessageBox") != std::string::npos) {
            code = compileMessageBox(stmt, parsedCode);
        } else if (stmt.find("return") != std::string::npos) {
            code = compileReturn(stmt);
        } else if (stmt.find("ExitProcess") != std::string::npos) {
            code = compileExitProcess(stmt);
        } else {
            // Default: generate NOP
            code = { 0x90 };  // NOP
        }
        
        return code;
    }
    
    std::vector<uint8_t> compileMessageBox(const std::string& statement, const ParsedCode& parsedCode) {
        std::vector<uint8_t> code;
        
        // Extract parameters from MessageBox call
        std::regex msgboxRegex(R"(MessageBox\s*\(\s*([^,]+)\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*([^)]+)\s*\))");
        std::smatch match;
        
        if (std::regex_search(statement, match, msgboxRegex)) {
            // Push parameters in reverse order
            std::string hwnd = match[1];
            std::string text = match[2];
            std::string caption = match[3];
            std::string type = match[4];
            
            // Push hwnd (usually NULL/0)
            if (hwnd.find("NULL") != std::string::npos || hwnd.find("0") != std::string::npos) {
                code.push_back(0x68);  // push
                code.insert(code.end(), { 0x00, 0x00, 0x00, 0x00 });  // 0
            }
            
            // Push type (usually MB_OK = 0)
            if (type.find("MB_OK") != std::string::npos) {
                code.push_back(0x68);  // push
                code.insert(code.end(), { 0x00, 0x00, 0x00, 0x00 });  // 0
            }
            
            // Push caption string
            code.push_back(0x68);  // push
            uint32_t captionAddr = 0x1000 + code.size() + 4;  // Placeholder address
            code.insert(code.end(), { 
                static_cast<uint8_t>(captionAddr & 0xFF),
                static_cast<uint8_t>((captionAddr >> 8) & 0xFF),
                static_cast<uint8_t>((captionAddr >> 16) & 0xFF),
                static_cast<uint8_t>((captionAddr >> 24) & 0xFF)
            });
            
            // Push text string
            code.push_back(0x68);  // push
            uint32_t textAddr = 0x1000 + code.size() + 4;  // Placeholder address
            code.insert(code.end(), { 
                static_cast<uint8_t>(textAddr & 0xFF),
                static_cast<uint8_t>((textAddr >> 8) & 0xFF),
                static_cast<uint8_t>((textAddr >> 16) & 0xFF),
                static_cast<uint8_t>((textAddr >> 24) & 0xFF)
            });
            
            // Call MessageBoxA
            code.push_back(0xFF);  // call
            code.push_back(0x15);  // [address]
            uint32_t funcAddr = 0x2000;  // Placeholder address for MessageBoxA
            code.insert(code.end(), { 
                static_cast<uint8_t>(funcAddr & 0xFF),
                static_cast<uint8_t>((funcAddr >> 8) & 0xFF),
                static_cast<uint8_t>((funcAddr >> 16) & 0xFF),
                static_cast<uint8_t>((funcAddr >> 24) & 0xFF)
            });
        }
        
        return code;
    }
    
    std::vector<uint8_t> compileReturn(const std::string& statement) {
        std::vector<uint8_t> code;
        
        // Extract return value
        std::regex returnRegex(R"(return\s+(\d+))");
        std::smatch match;
        
        if (std::regex_search(statement, match, returnRegex)) {
            int value = std::stoi(match[1]);
            
            // Move return value to eax
            if (value == 0) {
                code = { 0x33, 0xC0 };  // xor eax, eax
            } else {
                code = { 0xB8 };  // mov eax
                code.insert(code.end(), { 
                    static_cast<uint8_t>(value & 0xFF),
                    static_cast<uint8_t>((value >> 8) & 0xFF),
                    static_cast<uint8_t>((value >> 16) & 0xFF),
                    static_cast<uint8_t>((value >> 24) & 0xFF)
                });
            }
        }
        
        return code;
    }
    
    std::vector<uint8_t> compileExitProcess(const std::string& statement) {
        std::vector<uint8_t> code;
        
        // Extract exit code
        std::regex exitRegex(R"(ExitProcess\s*\(\s*(\d+)\s*\))");
        std::smatch match;
        
        if (std::regex_search(statement, match, exitRegex)) {
            int exitCode = std::stoi(match[1]);
            
            // Push exit code
            code.push_back(0x68);  // push
            code.insert(code.end(), { 
                static_cast<uint8_t>(exitCode & 0xFF),
                static_cast<uint8_t>((exitCode >> 8) & 0xFF),
                static_cast<uint8_t>((exitCode >> 16) & 0xFF),
                static_cast<uint8_t>((exitCode >> 24) & 0xFF)
            });
            
            // Call ExitProcess
            code.push_back(0xFF);  // call
            code.push_back(0x15);  // [address]
            uint32_t funcAddr = 0x2000;  // Placeholder address for ExitProcess
            code.insert(code.end(), { 
                static_cast<uint8_t>(funcAddr & 0xFF),
                static_cast<uint8_t>((funcAddr >> 8) & 0xFF),
                static_cast<uint8_t>((funcAddr >> 16) & 0xFF),
                static_cast<uint8_t>((funcAddr >> 24) & 0xFF)
            });
        }
        
        return code;
    }
    
    std::vector<uint8_t> generateDefaultExecutable() {
        // Generate a minimal executable that exits cleanly
        return {
            0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08,      // push ebp; mov ebp, esp; sub esp, 8
            0x68, 0x00, 0x00, 0x00, 0x00,            // push 0 (exit code)
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,      // call ExitProcess
            0x8B, 0xE5, 0x5D, 0xC3                   // mov esp, ebp; pop ebp; ret
        };
    }
    
    std::vector<uint8_t> createPEExecutable(const std::vector<uint8_t>& machineCode) {
        std::vector<uint8_t> peData;
        
        // Calculate sizes
        uint32_t codeSize = static_cast<uint32_t>(machineCode.size());
        uint32_t alignedCodeSize = (codeSize + 0x1FF) & ~0x1FF;  // Align to 0x200
        uint32_t totalSize = 0x200 + alignedCodeSize;  // Headers + code
        
        // Initialize PE data
        peData.resize(totalSize, 0);
        
        // DOS Header
        struct DOSHeader {
            uint16_t e_magic;
            uint16_t e_cblp;
            uint16_t e_cp;
            uint16_t e_crlc;
            uint16_t e_cparhdr;
            uint16_t e_minalloc;
            uint16_t e_maxalloc;
            uint16_t e_ss;
            uint16_t e_sp;
            uint16_t e_csum;
            uint16_t e_ip;
            uint16_t e_cs;
            uint16_t e_lfarlc;
            uint16_t e_ovno;
            uint16_t e_res[4];
            uint16_t e_oemid;
            uint16_t e_oeminfo;
            uint16_t e_res2[10];
            uint32_t e_lfanew;
        };
        
        DOSHeader dosHeader = {};
        dosHeader.e_magic = 0x5A4D;  // MZ
        dosHeader.e_lfanew = 0x80;   // PE header offset
        memcpy(peData.data(), &dosHeader, sizeof(dosHeader));
        
        // PE Header
        struct PEHeader {
            uint32_t signature;
            uint16_t machine;
            uint16_t numberOfSections;
            uint32_t timeDateStamp;
            uint32_t pointerToSymbolTable;
            uint32_t numberOfSymbols;
            uint16_t sizeOfOptionalHeader;
            uint16_t characteristics;
        };
        
        PEHeader peHeader = {};
        peHeader.signature = 0x00004550;  // PE\0\0
        peHeader.machine = 0x014C;  // x86
        peHeader.numberOfSections = 1;
        peHeader.timeDateStamp = static_cast<uint32_t>(time(nullptr));
        peHeader.sizeOfOptionalHeader = 224;  // Size of OptionalHeader
        peHeader.characteristics = 0x0102;  // Executable, 32-bit
        memcpy(peData.data() + dosHeader.e_lfanew, &peHeader, sizeof(peHeader));
        
        // Optional Header
        struct OptionalHeader {
            uint16_t magic;
            uint8_t majorLinkerVersion;
            uint8_t minorLinkerVersion;
            uint32_t sizeOfCode;
            uint32_t sizeOfInitializedData;
            uint32_t sizeOfUninitializedData;
            uint32_t addressOfEntryPoint;
            uint32_t baseOfCode;
            uint32_t baseOfData;
            uint32_t imageBase;
            uint32_t sectionAlignment;
            uint32_t fileAlignment;
            uint16_t majorOperatingSystemVersion;
            uint16_t minorOperatingSystemVersion;
            uint16_t majorImageVersion;
            uint16_t minorImageVersion;
            uint16_t majorSubsystemVersion;
            uint16_t minorSubsystemVersion;
            uint32_t win32VersionValue;
            uint32_t sizeOfImage;
            uint32_t sizeOfHeaders;
            uint32_t checkSum;
            uint16_t subsystem;
            uint16_t dllCharacteristics;
            uint32_t sizeOfStackReserve;
            uint32_t sizeOfStackCommit;
            uint32_t sizeOfHeapReserve;
            uint32_t sizeOfHeapCommit;
            uint32_t loaderFlags;
            uint32_t numberOfRvaAndSizes;
        };
        
        OptionalHeader optHeader = {};
        optHeader.magic = 0x010B;  // PE32
        optHeader.majorLinkerVersion = 14;
        optHeader.minorLinkerVersion = 0;
        optHeader.sizeOfCode = alignedCodeSize;
        optHeader.sizeOfInitializedData = 0;
        optHeader.sizeOfUninitializedData = 0;
        optHeader.addressOfEntryPoint = 0x1000;
        optHeader.baseOfCode = 0x1000;
        optHeader.baseOfData = 0x2000;
        optHeader.imageBase = 0x400000;
        optHeader.sectionAlignment = 0x1000;
        optHeader.fileAlignment = 0x200;
        optHeader.majorOperatingSystemVersion = 4;
        optHeader.minorOperatingSystemVersion = 0;
        optHeader.majorImageVersion = 1;
        optHeader.minorImageVersion = 0;
        optHeader.majorSubsystemVersion = 4;
        optHeader.minorSubsystemVersion = 0;
        optHeader.sizeOfImage = 0x3000;
        optHeader.sizeOfHeaders = 0x200;
        optHeader.subsystem = 2;  // Windows GUI
        optHeader.sizeOfStackReserve = 0x100000;
        optHeader.sizeOfStackCommit = 0x1000;
        optHeader.sizeOfHeapReserve = 0x100000;
        optHeader.sizeOfHeapCommit = 0x1000;
        optHeader.numberOfRvaAndSizes = 16;
        memcpy(peData.data() + dosHeader.e_lfanew + sizeof(peHeader), &optHeader, sizeof(optHeader));
        
        // Section Header
        struct SectionHeader {
            char name[8];
            uint32_t virtualSize;
            uint32_t virtualAddress;
            uint32_t sizeOfRawData;
            uint32_t pointerToRawData;
            uint32_t pointerToRelocations;
            uint32_t pointerToLineNumbers;
            uint16_t numberOfRelocations;
            uint16_t numberOfLineNumbers;
            uint32_t characteristics;
        };
        
        SectionHeader textSection = {};
        strcpy(textSection.name, ".text");
        textSection.virtualSize = codeSize;
        textSection.virtualAddress = 0x1000;
        textSection.sizeOfRawData = alignedCodeSize;
        textSection.pointerToRawData = 0x200;
        textSection.characteristics = 0x60000020;  // Code, executable, readable
        memcpy(peData.data() + dosHeader.e_lfanew + sizeof(peHeader) + sizeof(optHeader), &textSection, sizeof(textSection));
        
        // Write the machine code
        memcpy(peData.data() + textSection.pointerToRawData, machineCode.data(), machineCode.size());
        
        return peData;
    }
};
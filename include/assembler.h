#pragma once
#include "utils.h"
#include <string>
#include <vector>

// Base class for assembly tools
class BaseAssembler : public BaseTool {
protected:
    std::string outputFile;
    std::string sourceFile;
    
public:
    virtual ~BaseAssembler() = default;
    virtual void run() override = 0;
    virtual bool assemble(const std::string& source, const std::string& output) = 0;
    virtual bool link(const std::string& objectFile, const std::string& output) = 0;
};

// MASM-specific assembler
class MASMAssembler : public BaseAssembler {
private:
    std::string masmPath;
    std::string linkPath;
    
    void showMASMMenu();
    void createBasicProgram();
    void createAdvancedProgram();
    void assembleFile();
    void runAssembly();
    void showExamples();
    void showAssemblyUtils();
    
public:
    MASMAssembler();
    void run() override;
    bool assemble(const std::string& source, const std::string& output) override;
    bool link(const std::string& objectFile, const std::string& output) override;
    
    // MASM-specific utilities
    std::string generateBasicTemplate();
    std::string generateAdvancedTemplate();
    std::string generateHelloWorld();
    std::string generateCalculator();
    std::string generateGame();
};

// Assembly utilities
class AssemblyUtils {
public:
    static std::string generateX86Template();
    static std::string generateX64Template();
    static std::string generateFunctionTemplate(const std::string& name);
    static std::string generateLoopTemplate();
    static std::string generateConditionalTemplate();
    static std::string generateStringTemplate();
    static std::string generateMathTemplate();
    
    // Assembly analysis tools
    static void analyzeAssembly(const std::string& code);
    static void optimizeAssembly(std::string& code);
    static std::string disassemble(const std::string& binaryFile);
};
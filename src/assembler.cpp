#include "assembler.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstdlib>

MASMAssembler::MASMAssembler() {
    // Try to find MASM and LINK in common locations
    masmPath = "ml.exe";  // Default MASM executable
    linkPath = "link.exe"; // Default LINK executable
    
    // Check if we're on Windows and MASM is available
    #ifdef _WIN32
        // MASM is typically installed with Visual Studio
        // We'll check common paths
        std::vector<std::string> possiblePaths = {
            "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\VC\\Tools\\MSVC\\14.29.30133\\bin\\Hostx64\\x64\\ml.exe",
            "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Professional\\VC\\Tools\\MSVC\\14.29.30133\\bin\\Hostx64\\x64\\ml.exe",
            "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Enterprise\\VC\\Tools\\MSVC\\14.29.30133\\bin\\Hostx64\\x64\\ml.exe",
            "ml.exe"  // If it's in PATH
        };
        
        for (const auto& path : possiblePaths) {
            std::ifstream test(path);
            if (test.good()) {
                masmPath = path;
                break;
            }
        }
    #else
        // On Linux, we'll use NASM as an alternative
        masmPath = "nasm";
        linkPath = "ld";
    #endif
}

void MASMAssembler::run() {
    while (true) {
        clearScreen();
        printHeader("MASM Assembly Development");
        
        std::cout << "1. Create Basic Assembly Program" << std::endl;
        std::cout << "2. Create Advanced Assembly Program" << std::endl;
        std::cout << "3. Assemble Existing File" << std::endl;
        std::cout << "4. Run Assembly Program" << std::endl;
        std::cout << "5. Show Assembly Examples" << std::endl;
        std::cout << "6. Assembly Utilities" << std::endl;
        std::cout << "7. Back to Main Menu" << std::endl;
        
        int choice = getValidInt("Choose an option: ");
        
        switch (choice) {
            case 1:
                createBasicProgram();
                break;
            case 2:
                createAdvancedProgram();
                break;
            case 3:
                assembleFile();
                break;
            case 4:
                runAssembly();
                break;
            case 5:
                showExamples();
                break;
            case 6:
                showAssemblyUtils();
                break;
            case 7:
                return;
            default:
                std::cout << "Invalid option!" << std::endl;
        }
        pauseScreen();
    }
}

void MASMAssembler::createBasicProgram() {
    printHeader("Create Basic Assembly Program");
    
    std::string filename;
    std::cout << "Enter filename (without extension): ";
    std::cin.ignore();
    std::getline(std::cin, filename);
    
    if (filename.empty()) {
        filename = "basic_program";
    }
    
    std::string sourceFile = filename + ".asm";
    std::string outputFile = filename + ".exe";
    
    // Generate basic MASM template
    std::string templateCode = generateBasicTemplate();
    
    // Write to file
    std::ofstream file(sourceFile);
    if (file.is_open()) {
        file << templateCode;
        file.close();
        std::cout << "✅ Created " << sourceFile << std::endl;
        
        // Try to assemble
        if (assemble(sourceFile, outputFile)) {
            std::cout << "✅ Successfully assembled to " << outputFile << std::endl;
        } else {
            std::cout << "⚠️  Assembly failed, but source file was created" << std::endl;
        }
    } else {
        std::cout << "❌ Could not create file!" << std::endl;
    }
}

void MASMAssembler::createAdvancedProgram() {
    printHeader("Create Advanced Assembly Program");
    
    std::cout << "Choose program type:" << std::endl;
    std::cout << "1. Hello World" << std::endl;
    std::cout << "2. Simple Calculator" << std::endl;
    std::cout << "3. Number Guessing Game" << std::endl;
    std::cout << "4. Custom Template" << std::endl;
    
    int choice = getValidInt("Choose type: ");
    
    std::string filename;
    std::cout << "Enter filename (without extension): ";
    std::cin.ignore();
    std::getline(std::cin, filename);
    
    if (filename.empty()) {
        filename = "advanced_program";
    }
    
    std::string sourceFile = filename + ".asm";
    std::string outputFile = filename + ".exe";
    
    std::string templateCode;
    switch (choice) {
        case 1:
            templateCode = generateHelloWorld();
            break;
        case 2:
            templateCode = generateCalculator();
            break;
        case 3:
            templateCode = generateGame();
            break;
        case 4:
            templateCode = generateAdvancedTemplate();
            break;
        default:
            std::cout << "Invalid choice!" << std::endl;
            return;
    }
    
    // Write to file
    std::ofstream file(sourceFile);
    if (file.is_open()) {
        file << templateCode;
        file.close();
        std::cout << "✅ Created " << sourceFile << std::endl;
        
        // Try to assemble
        if (assemble(sourceFile, outputFile)) {
            std::cout << "✅ Successfully assembled to " << outputFile << std::endl;
        } else {
            std::cout << "⚠️  Assembly failed, but source file was created" << std::endl;
        }
    } else {
        std::cout << "❌ Could not create file!" << std::endl;
    }
}

void MASMAssembler::assembleFile() {
    printHeader("Assemble Assembly File");
    
    std::string sourceFile;
    std::cout << "Enter source file (.asm): ";
    std::cin.ignore();
    std::getline(std::cin, sourceFile);
    
    if (sourceFile.empty()) {
        std::cout << "No filename provided!" << std::endl;
        return;
    }
    
    // Add .asm extension if not present
    if (sourceFile.find(".asm") == std::string::npos) {
        sourceFile += ".asm";
    }
    
    std::string outputFile = sourceFile.substr(0, sourceFile.find(".asm")) + ".exe";
    
    if (assemble(sourceFile, outputFile)) {
        std::cout << "✅ Successfully assembled to " << outputFile << std::endl;
    } else {
        std::cout << "❌ Assembly failed!" << std::endl;
    }
}

void MASMAssembler::runAssembly() {
    printHeader("Run Assembly Program");
    
    std::string programFile;
    std::cout << "Enter program file (.exe): ";
    std::cin.ignore();
    std::getline(std::cin, programFile);
    
    if (programFile.empty()) {
        std::cout << "No filename provided!" << std::endl;
        return;
    }
    
    // Add .exe extension if not present
    if (programFile.find(".exe") == std::string::npos) {
        programFile += ".exe";
    }
    
    std::cout << "Running " << programFile << "..." << std::endl;
    std::cout << "Output:" << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    
    // Run the program
    std::string command = programFile;
    int result = system(command.c_str());
    
    std::cout << "----------------------------------------" << std::endl;
    std::cout << "Program finished with exit code: " << result << std::endl;
}

void MASMAssembler::showExamples() {
    printHeader("Assembly Examples");
    
    std::cout << "1. Basic MASM Template" << std::endl;
    std::cout << "2. Hello World" << std::endl;
    std::cout << "3. Simple Calculator" << std::endl;
    std::cout << "4. Function Template" << std::endl;
    std::cout << "5. Loop Template" << std::endl;
    
    int choice = getValidInt("Choose example to view: ");
    
    std::string example;
    switch (choice) {
        case 1:
            example = generateBasicTemplate();
            break;
        case 2:
            example = generateHelloWorld();
            break;
        case 3:
            example = generateCalculator();
            break;
        case 4:
            example = AssemblyUtils::generateFunctionTemplate("myFunction");
            break;
        case 5:
            example = AssemblyUtils::generateLoopTemplate();
            break;
        default:
            std::cout << "Invalid choice!" << std::endl;
            return;
    }
    
    std::cout << "\n=== Assembly Code ===" << std::endl;
    std::cout << example << std::endl;
}

void MASMAssembler::showAssemblyUtils() {
    printHeader("Assembly Utilities");
    
    std::cout << "1. Analyze Assembly Code" << std::endl;
    std::cout << "2. Generate X86 Template" << std::endl;
    std::cout << "3. Generate X64 Template" << std::endl;
    std::cout << "4. Generate Math Template" << std::endl;
    std::cout << "5. Generate String Template" << std::endl;
    
    int choice = getValidInt("Choose utility: ");
    
    switch (choice) {
        case 1: {
            std::string code;
            std::cout << "Enter assembly code to analyze:" << std::endl;
            std::cin.ignore();
            std::getline(std::cin, code);
            AssemblyUtils::analyzeAssembly(code);
            break;
        }
        case 2: {
            std::cout << "\n=== X86 Template ===" << std::endl;
            std::cout << AssemblyUtils::generateX86Template() << std::endl;
            break;
        }
        case 3: {
            std::cout << "\n=== X64 Template ===" << std::endl;
            std::cout << AssemblyUtils::generateX64Template() << std::endl;
            break;
        }
        case 4: {
            std::cout << "\n=== Math Template ===" << std::endl;
            std::cout << AssemblyUtils::generateMathTemplate() << std::endl;
            break;
        }
        case 5: {
            std::cout << "\n=== String Template ===" << std::endl;
            std::cout << AssemblyUtils::generateStringTemplate() << std::endl;
            break;
        }
        default:
            std::cout << "Invalid choice!" << std::endl;
    }
}

bool MASMAssembler::assemble(const std::string& source, const std::string& output) {
    std::cout << "🔨 Assembling " << source << "..." << std::endl;
    
    #ifdef _WIN32
        // Use MASM on Windows
        std::string command = masmPath + " /c /coff " + source + " /link /subsystem:console " + output;
    #else
        // Use NASM on Linux
        std::string objectFile = source.substr(0, source.find(".asm")) + ".o";
        std::string command = masmPath + " -f elf64 " + source + " -o " + objectFile + " && " + 
                             linkPath + " " + objectFile + " -o " + output;
    #endif
    
    int result = system(command.c_str());
    return result == 0;
}

bool MASMAssembler::link(const std::string& objectFile, const std::string& output) {
    std::cout << "🔗 Linking " << objectFile << "..." << std::endl;
    
    std::string command = linkPath + " " + objectFile + " /out:" + output;
    int result = system(command.c_str());
    return result == 0;
}

// Template generation methods
std::string MASMAssembler::generateBasicTemplate() {
    return R"(
.386
.model flat, stdcall
.stack 4096

ExitProcess PROTO, dwExitCode:DWORD

.data
    ; Data section - variables go here
    message db "Hello from MASM!", 0dh, 0ah, 0

.code
main PROC
    ; Your code goes here
    mov eax, 0  ; Return 0
    
    ; Exit program
    INVOKE ExitProcess, eax
main ENDP
END main
)";
}

std::string MASMAssembler::generateAdvancedTemplate() {
    return R"(
.386
.model flat, stdcall
.stack 4096

; Function prototypes
ExitProcess PROTO, dwExitCode:DWORD
GetStdHandle PROTO, nStdHandle:DWORD
WriteConsoleA PROTO, handle:DWORD, buffer:PTR BYTE, bytes:DWORD, written:PTR DWORD, overlapped:PTR DWORD

; Constants
STD_OUTPUT_HANDLE EQU -11

.data
    ; Variables
    message db "Advanced MASM Program", 0dh, 0ah, 0
    messageLen EQU $ - message
    written DWORD ?

.code
main PROC
    ; Get console handle
    PUSH STD_OUTPUT_HANDLE
    CALL GetStdHandle
    ADD ESP, 4
    
    ; Write message
    PUSH 0                    ; overlapped
    PUSH OFFSET written       ; written
    PUSH messageLen           ; bytes
    PUSH OFFSET message       ; buffer
    PUSH EAX                  ; handle
    CALL WriteConsoleA
    ADD ESP, 20
    
    ; Exit
    PUSH 0
    CALL ExitProcess
main ENDP
END main
)";
}

std::string MASMAssembler::generateHelloWorld() {
    return R"(
.386
.model flat, stdcall
.stack 4096

ExitProcess PROTO, dwExitCode:DWORD
GetStdHandle PROTO, nStdHandle:DWORD
WriteConsoleA PROTO, handle:DWORD, buffer:PTR BYTE, bytes:DWORD, written:PTR DWORD, overlapped:PTR DWORD

STD_OUTPUT_HANDLE EQU -11

.data
    hello db "Hello, World!", 0dh, 0ah, 0
    helloLen EQU $ - hello
    written DWORD ?

.code
main PROC
    ; Get console handle
    PUSH STD_OUTPUT_HANDLE
    CALL GetStdHandle
    ADD ESP, 4
    
    ; Write hello message
    PUSH 0
    PUSH OFFSET written
    PUSH helloLen
    PUSH OFFSET hello
    PUSH EAX
    CALL WriteConsoleA
    ADD ESP, 20
    
    ; Exit with code 0
    PUSH 0
    CALL ExitProcess
main ENDP
END main
)";
}

std::string MASMAssembler::generateCalculator() {
    return R"(
.386
.model flat, stdcall
.stack 4096

ExitProcess PROTO, dwExitCode:DWORD
GetStdHandle PROTO, nStdHandle:DWORD
WriteConsoleA PROTO, handle:DWORD, buffer:PTR BYTE, bytes:DWORD, written:PTR DWORD, overlapped:PTR DWORD
ReadConsoleA PROTO, handle:DWORD, buffer:PTR BYTE, bytes:DWORD, read:PTR DWORD, overlapped:PTR DWORD

STD_OUTPUT_HANDLE EQU -10
STD_INPUT_HANDLE EQU -11

.data
    prompt db "Enter two numbers to add: ", 0
    promptLen EQU $ - prompt
    result db "Result: ", 0
    resultLen EQU $ - result
    newline db 0dh, 0ah, 0
    newlineLen EQU $ - newline
    buffer db 32 DUP(0)
    written DWORD ?
    read DWORD ?

.code
main PROC
    ; Get handles
    PUSH STD_OUTPUT_HANDLE
    CALL GetStdHandle
    MOV EBX, EAX  ; Save output handle
    
    PUSH STD_INPUT_HANDLE
    CALL GetStdHandle
    MOV ECX, EAX  ; Save input handle
    
    ; Write prompt
    PUSH 0
    PUSH OFFSET written
    PUSH promptLen
    PUSH OFFSET prompt
    PUSH EBX
    CALL WriteConsoleA
    ADD ESP, 20
    
    ; Read first number (simplified - just read input)
    PUSH 0
    PUSH OFFSET read
    PUSH 32
    PUSH OFFSET buffer
    PUSH ECX
    CALL ReadConsoleA
    ADD ESP, 20
    
    ; Write result message
    PUSH 0
    PUSH OFFSET written
    PUSH resultLen
    PUSH OFFSET result
    PUSH EBX
    CALL WriteConsoleA
    ADD ESP, 20
    
    ; Write newline
    PUSH 0
    PUSH OFFSET written
    PUSH newlineLen
    PUSH OFFSET newline
    PUSH EBX
    CALL WriteConsoleA
    ADD ESP, 20
    
    ; Exit
    PUSH 0
    CALL ExitProcess
main ENDP
END main
)";
}

std::string MASMAssembler::generateGame() {
    return R"(
.386
.model flat, stdcall
.stack 4096

ExitProcess PROTO, dwExitCode:DWORD
GetStdHandle PROTO, nStdHandle:DWORD
WriteConsoleA PROTO, handle:DWORD, buffer:PTR BYTE, bytes:DWORD, written:PTR DWORD, overlapped:PTR DWORD

STD_OUTPUT_HANDLE EQU -11

.data
    welcome db "Welcome to Assembly Game!", 0dh, 0ah, 0
    welcomeLen EQU $ - welcome
    guess db "Guess a number (1-10): ", 0
    guessLen EQU $ - guess
    correct db "Correct! You win!", 0dh, 0ah, 0
    correctLen EQU $ - correct
    wrong db "Wrong! Try again!", 0dh, 0ah, 0
    wrongLen EQU $ - wrong
    written DWORD ?

.code
main PROC
    ; Get console handle
    PUSH STD_OUTPUT_HANDLE
    CALL GetStdHandle
    ADD ESP, 4
    
    ; Write welcome message
    PUSH 0
    PUSH OFFSET written
    PUSH welcomeLen
    PUSH OFFSET welcome
    PUSH EAX
    CALL WriteConsoleA
    ADD ESP, 20
    
    ; Write guess prompt
    PUSH 0
    PUSH OFFSET written
    PUSH guessLen
    PUSH OFFSET guess
    PUSH EAX
    CALL WriteConsoleA
    ADD ESP, 20
    
    ; Write result (simplified - always shows "correct")
    PUSH 0
    PUSH OFFSET written
    PUSH correctLen
    PUSH OFFSET correct
    PUSH EAX
    CALL WriteConsoleA
    ADD ESP, 20
    
    ; Exit
    PUSH 0
    CALL ExitProcess
main ENDP
END main
)";
}

// Assembly utilities implementation
std::string AssemblyUtils::generateX86Template() {
    return R"(
.386
.model flat, stdcall
.stack 4096

ExitProcess PROTO, dwExitCode:DWORD

.data
    ; Your data here

.code
main PROC
    ; Your code here
    
    ; Exit
    PUSH 0
    CALL ExitProcess
main ENDP
END main
)";
}

std::string AssemblyUtils::generateX64Template() {
    return R"(
.code
main PROC
    ; Your x64 code here
    
    ; Exit
    MOV RAX, 0
    RET
main ENDP
END
)";
}

std::string AssemblyUtils::generateFunctionTemplate(const std::string& name) {
    std::stringstream ss;
    ss << R"(
; Function: )" << name << R"(
)" << name << R"( PROC
    ; Function prologue
    PUSH EBP
    MOV EBP, ESP
    
    ; Your function code here
    
    ; Function epilogue
    MOV ESP, EBP
    POP EBP
    RET
)" << name << R"( ENDP
)";
    return ss.str();
}

std::string AssemblyUtils::generateLoopTemplate() {
    return R"(
; Loop template
MOV ECX, 10      ; Loop counter
loop_start:
    ; Your loop code here
    
    LOOP loop_start  ; Decrement ECX and jump if not zero
)";
}

std::string AssemblyUtils::generateConditionalTemplate() {
    return R"(
; Conditional template
CMP EAX, EBX     ; Compare EAX with EBX
JE equal         ; Jump if equal
JNE not_equal    ; Jump if not equal
JG greater       ; Jump if greater
JL less          ; Jump if less

equal:
    ; Code for equal case
    JMP end_conditional

not_equal:
    ; Code for not equal case
    JMP end_conditional

greater:
    ; Code for greater case
    JMP end_conditional

less:
    ; Code for less case

end_conditional:
)";
}

std::string AssemblyUtils::generateStringTemplate() {
    return R"(
; String operations template
.data
    string1 db "Hello", 0
    string2 db "World", 0
    buffer db 256 DUP(0)

.code
; String length
MOV EDI, OFFSET string1
MOV ECX, 0
MOV AL, 0
REPNE SCASB
NEG ECX
DEC ECX  ; ECX now contains string length

; String copy
MOV ESI, OFFSET string1
MOV EDI, OFFSET buffer
MOV ECX, 6  ; Length to copy
REP MOVSB
)";
}

std::string AssemblyUtils::generateMathTemplate() {
    return R"(
; Math operations template
; Addition
ADD EAX, EBX     ; EAX = EAX + EBX

; Subtraction
SUB EAX, EBX     ; EAX = EAX - EBX

; Multiplication
MUL EBX          ; EDX:EAX = EAX * EBX

; Division
DIV EBX          ; EAX = EDX:EAX / EBX, EDX = remainder

; Bitwise operations
AND EAX, EBX     ; EAX = EAX & EBX
OR EAX, EBX      ; EAX = EAX | EBX
XOR EAX, EBX     ; EAX = EAX ^ EBX
NOT EAX          ; EAX = ~EAX

; Shifts
SHL EAX, 2       ; EAX = EAX << 2
SHR EAX, 2       ; EAX = EAX >> 2
)";
}

void AssemblyUtils::analyzeAssembly(const std::string& code) {
    std::cout << "\n=== Assembly Code Analysis ===" << std::endl;
    
    // Simple analysis
    size_t lines = std::count(code.begin(), code.end(), '\n') + 1;
    size_t instructions = std::count(code.begin(), code.end(), '\n');
    
    std::cout << "Lines of code: " << lines << std::endl;
    std::cout << "Estimated instructions: " << instructions << std::endl;
    
    // Check for common patterns
    if (code.find("MOV") != std::string::npos) {
        std::cout << "✓ Contains MOV instructions" << std::endl;
    }
    if (code.find("CALL") != std::string::npos) {
        std::cout << "✓ Contains function calls" << std::endl;
    }
    if (code.find("JMP") != std::string::npos || code.find("JE") != std::string::npos) {
        std::cout << "✓ Contains jump instructions" << std::endl;
    }
    if (code.find("PUSH") != std::string::npos) {
        std::cout << "✓ Uses stack operations" << std::endl;
    }
    
    std::cout << "\nAnalysis complete!" << std::endl;
}

void AssemblyUtils::optimizeAssembly(std::string& code) {
    std::cout << "Optimizing assembly code..." << std::endl;
    
    // Simple optimizations (in a real implementation, this would be more sophisticated)
    // For now, just add some comments about potential optimizations
    
    std::cout << "Potential optimizations:" << std::endl;
    std::cout << "- Use registers efficiently" << std::endl;
    std::cout << "- Minimize memory accesses" << std::endl;
    std::cout << "- Use appropriate instruction sizes" << std::endl;
    std::cout << "- Consider loop unrolling" << std::endl;
}

std::string AssemblyUtils::disassemble(const std::string& binaryFile) {
    std::cout << "Disassembling " << binaryFile << "..." << std::endl;
    
    // This would require a disassembler library
    // For now, return a placeholder
    return "Disassembly would require additional tools (e.g., objdump, IDA Pro, or similar)";
}
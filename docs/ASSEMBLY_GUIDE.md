# Assembly Programming Guide

## Introduction to MASM

MASM (Microsoft Macro Assembler) is a powerful assembly language for x86 and x64 architectures. This guide will help you get started with assembly programming in your C++ AI Development Environment.

## Basic MASM Structure

### Program Template
```asm
.386                    ; Specify processor
.model flat, stdcall    ; Memory model and calling convention
.stack 4096             ; Stack size

; Function prototypes
ExitProcess PROTO, dwExitCode:DWORD

.data
    ; Variables and data go here

.code
main PROC
    ; Your code goes here
    
    ; Exit program
    PUSH 0
    CALL ExitProcess
main ENDP
END main
```

## Key Concepts

### 1. Directives
- `.386` - Target processor
- `.model` - Memory model and calling convention
- `.stack` - Stack size
- `.data` - Data section
- `.code` - Code section

### 2. Instructions
- `MOV` - Move data
- `ADD/SUB` - Arithmetic operations
- `PUSH/POP` - Stack operations
- `CALL` - Function calls
- `JMP/JE/JNE` - Jump instructions

### 3. Registers
- `EAX, EBX, ECX, EDX` - General purpose
- `ESI, EDI` - Source/Destination index
- `ESP, EBP` - Stack pointer/Base pointer

## Windows API Integration

### Console Output
```asm
; Get console handle
PUSH STD_OUTPUT_HANDLE  ; -11
CALL GetStdHandle
ADD ESP, 4

; Write to console
PUSH 0                  ; overlapped
PUSH OFFSET written     ; written
PUSH messageLen         ; bytes
PUSH OFFSET message     ; buffer
PUSH EAX               ; handle
CALL WriteConsoleA
ADD ESP, 20            ; clean stack
```

### Function Prototypes
```asm
GetStdHandle PROTO, nStdHandle:DWORD
WriteConsoleA PROTO, handle:DWORD, buffer:PTR BYTE, bytes:DWORD, written:PTR DWORD, overlapped:PTR DWORD
```

## Common Patterns

### 1. Function Calls
```asm
; Call function with parameters
PUSH param3
PUSH param2
PUSH param1
CALL functionName
ADD ESP, 12  ; Clean up stack (4 bytes per parameter)
```

### 2. Conditional Logic
```asm
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

end_conditional:
```

### 3. Loops
```asm
MOV ECX, 10      ; Loop counter
loop_start:
    ; Loop body
    
    LOOP loop_start  ; Decrement ECX and jump if not zero
```

### 4. String Operations
```asm
; String length
MOV EDI, OFFSET string
MOV ECX, 0
MOV AL, 0
REPNE SCASB      ; Repeat until null terminator
NEG ECX
DEC ECX          ; ECX now contains length

; String copy
MOV ESI, OFFSET source
MOV EDI, OFFSET destination
MOV ECX, length
REP MOVSB        ; Copy bytes
```

## Data Types

### 1. Variables
```asm
.data
    byte_var db 42              ; 8-bit
    word_var dw 1234            ; 16-bit
    dword_var dd 12345678       ; 32-bit
    string_var db "Hello", 0    ; String with null terminator
    array_var db 1, 2, 3, 4     ; Array
```

### 2. Constants
```asm
STD_OUTPUT_HANDLE EQU -11
BUFFER_SIZE EQU 256
```

## Advanced Topics

### 1. Macros
```asm
; Define a macro
PRINT_STRING MACRO string
    PUSH OFFSET string
    CALL print_string
    ADD ESP, 4
ENDM

; Use the macro
PRINT_STRING message
```

### 2. Procedures
```asm
print_string PROC
    PUSH EBP
    MOV EBP, ESP
    
    ; Get string from stack
    MOV EAX, [EBP + 8]
    
    ; Print string code here
    
    MOV ESP, EBP
    POP EBP
    RET
print_string ENDP
```

### 3. Stack Frame
```asm
function PROC
    ; Prologue
    PUSH EBP
    MOV EBP, ESP
    SUB ESP, local_vars_size
    
    ; Function body
    
    ; Epilogue
    MOV ESP, EBP
    POP EBP
    RET
function ENDP
```

## Debugging Tips

### 1. Add Debug Output
```asm
; Print debug message
PUSH OFFSET debug_msg
CALL print_string
ADD ESP, 4
```

### 2. Check Register Values
```asm
; Save register value
PUSH EAX
; Use EAX for something
POP EAX  ; Restore original value
```

### 3. Common Errors
- **Stack imbalance** - Make sure PUSH/POP pairs match
- **Wrong calling convention** - Use stdcall for Windows API
- **Register corruption** - Save registers before function calls
- **Memory access violations** - Check array bounds and pointers

## Optimization Techniques

### 1. Register Usage
- Use registers instead of memory when possible
- Minimize register spills to stack
- Use appropriate register sizes

### 2. Instruction Selection
- Use shorter instructions when possible
- Avoid unnecessary instructions
- Use efficient addressing modes

### 3. Loop Optimization
- Unroll small loops
- Use efficient loop constructs
- Minimize loop overhead

## Integration with C++

### 1. Calling Assembly from C++
```cpp
extern "C" {
    int assembly_function(int param);
}
```

### 2. Assembly Function
```asm
.386
.model flat, C

.code
assembly_function PROC
    MOV EAX, [ESP + 4]  ; Get parameter
    ADD EAX, 1          ; Add 1
    RET                 ; Return value in EAX
assembly_function ENDP
END
```

## Tools and Resources

### 1. Built-in Tools
- **Template Generator** - Create basic programs
- **Code Analyzer** - Analyze assembly code
- **Example Library** - Learn from examples

### 2. External Tools
- **Visual Studio** - Integrated MASM support
- **WinDbg** - Debug assembly programs
- **IDA Pro** - Disassemble and analyze

### 3. Learning Resources
- Microsoft MASM documentation
- x86 instruction set reference
- Windows API documentation

## Best Practices

1. **Always comment your code** - Assembly is hard to read
2. **Use meaningful labels** - Make code self-documenting
3. **Follow calling conventions** - Ensure compatibility
4. **Test thoroughly** - Assembly bugs are hard to find
5. **Keep functions small** - Easier to debug and maintain
6. **Use macros for common patterns** - Reduce code duplication

## Common Examples

### 1. Hello World
See `examples/hello_world.asm` for a complete example.

### 2. Calculator
```asm
; Simple addition
MOV EAX, [num1]
ADD EAX, [num2]
MOV [result], EAX
```

### 3. Array Processing
```asm
MOV ECX, array_size
MOV ESI, OFFSET array
loop_start:
    MOV EAX, [ESI]
    ; Process element
    ADD ESI, 4  ; Next element
    LOOP loop_start
```

## Next Steps

1. **Start with simple programs** - Hello World, basic arithmetic
2. **Learn Windows API** - Console I/O, file operations
3. **Practice with loops and conditionals** - Build logic skills
4. **Study optimization** - Learn efficient coding techniques
5. **Integrate with C++** - Combine high and low level programming

Remember: Assembly programming requires patience and practice. Start simple and gradually build complexity!
; MASM Hello World Example
; This demonstrates basic MASM syntax and Windows API calls

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
    ; Data section - variables and strings
    message db "Hello, World from MASM!", 0dh, 0ah, 0
    messageLen EQU $ - message
    written DWORD ?

.code
main PROC
    ; Get console handle for output
    PUSH STD_OUTPUT_HANDLE
    CALL GetStdHandle
    ADD ESP, 4
    
    ; Write message to console
    PUSH 0                    ; overlapped parameter
    PUSH OFFSET written       ; written parameter
    PUSH messageLen           ; bytes to write
    PUSH OFFSET message       ; buffer to write
    PUSH EAX                  ; console handle
    CALL WriteConsoleA
    ADD ESP, 20               ; clean up stack
    
    ; Exit program with code 0
    PUSH 0
    CALL ExitProcess
main ENDP
END main
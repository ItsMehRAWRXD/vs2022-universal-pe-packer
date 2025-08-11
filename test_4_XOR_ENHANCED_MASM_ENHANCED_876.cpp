// ===== ENHANCED TEST STUB 4 =====
// Visual Studio 2022 Command Line Encryptor Compatible
// Generation ID: 630576
// Timestamp: 1754535265
// Encryption Type: 0
// Stub Type: 1
// Enhanced XOR with key rotation applied

.386
.model flat, stdcall
option casemap :none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
includelib \masm32\lib\kernel32.lib

.data
    embedded_data_630576 db 034h, 0a8h, 075h, 0cbh, 094h, 02fh, 05eh, 0bch, 07dh, 0f2h, 0e5h, 0cbh, 068h, 0d0h, 05eh, 0bch
    0c1h, 0f2h, 0e5h, 0cbh, 097h, 02fh, 05eh, 0bch, 039h, 0f2h, 0e5h, 0cbh, 097h, 02fh, 05eh, 0bch
    079h, 0f2h, 0e5h, 0cbh, 097h, 02fh, 05eh, 0bch, 079h, 0f2h, 0e5h, 0cbh, 097h, 02fh, 05eh, 0bch
    011h, 097h, 089h, 0a7h, 0f8h, 00fh, 029h, 0d3h, 00bh, 09eh, 081h, 0eah, 097h, 0bfh, 0ceh, 02ch
    0b5h, 03eh, 029h, 007h, 054h, 0bfh, 0ceh, 02ch
    data_size_630576 dd 72
    success_msg db "Test 4 Enhanced Stub Executed Successfully", 0

.code
start:
    ; Enhanced test stub entry point
    push ebp
    mov ebp, esp

    ; Process embedded data
    lea esi, embedded_data_630576
    mov ecx, data_size_630576
    call process_data_630576

    ; Display success message
    invoke MessageBoxA, 0, addr success_msg, addr success_msg, MB_OK

    ; Exit
    mov esp, ebp
    pop ebp
    invoke ExitProcess, 0

process_data_630576 proc
    ; Process embedded data here
    ; ESI = data pointer, ECX = size
    push esi
    push ecx
    ; Add processing logic here
    pop ecx
    pop esi
    ret
process_data_630576 endp

end start

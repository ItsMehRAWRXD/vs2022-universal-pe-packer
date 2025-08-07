// ===== ENHANCED TEST STUB 4 =====
// Visual Studio 2022 Command Line Encryptor Compatible
// Generation ID: 114972
// Timestamp: 1754535265
// Encryption Type: 1
// Stub Type: 1
// AES SubBytes transformation applied

.386
.model flat, stdcall
option casemap :none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
includelib \masm32\lib\kernel32.lib

.data
    embedded_data_114972 db 0e3h, 0beh, 060h, 063h, 07bh, 063h, 063h, 063h, 0f2h, 063h, 063h, 063h, 054h, 054h, 063h, 063h
    04eh, 063h, 063h, 063h, 063h, 063h, 063h, 063h, 009h, 063h, 063h, 063h, 063h, 063h, 063h, 063h
    063h, 063h, 063h, 063h, 063h, 063h, 063h, 063h, 063h, 063h, 063h, 063h, 063h, 063h, 063h, 063h
    045h, 04dh, 050h, 050h, 0a8h, 0b7h, 0f5h, 0a8h, 040h, 050h, 043h, 0fdh, 063h, 060h, 060h, 060h
    074h, 074h, 074h, 074h, 078h, 060h, 060h, 060h
    data_size_114972 dd 72
    success_msg db "Test 4 Enhanced Stub Executed Successfully", 0

.code
start:
    ; Enhanced test stub entry point
    push ebp
    mov ebp, esp

    ; Process embedded data
    lea esi, embedded_data_114972
    mov ecx, data_size_114972
    call process_data_114972

    ; Display success message
    invoke MessageBoxA, 0, addr success_msg, addr success_msg, MB_OK

    ; Exit
    mov esp, ebp
    pop ebp
    invoke ExitProcess, 0

process_data_114972 proc
    ; Process embedded data here
    ; ESI = data pointer, ECX = size
    push esi
    push ecx
    ; Add processing logic here
    pop ecx
    pop esi
    ret
process_data_114972 endp

end start

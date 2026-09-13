; Program logic. Included after the PE headers in daydir.asm.
default rel

start:
    ; 64 KiB path + SYSTEMTIME + 32-byte Win64 shadow space + alignment.
    ; The PE header commits 128 KiB before this stack allocation.
    ; Entry never returns, so nonvolatile registers need not be restored.
    sub rsp, 0x10038
    lea rbx, [rsp+64]             ; leave room before path for the UNC prefix
    xor ecx, ecx
    mov rdx, rbx
    mov r8d, 32750                ; spare room for YYYY_MM_DD and NUL
    call [__imp_GetModuleFileNameW]
    test eax, eax
    jz last_error
    cmp eax, 32750
    jae path_error
    lea rdi, [rbx+rax*2]
.separator:
    cmp rdi, rbx
    je path_error
    sub rdi, 2
    cmp word [rdi], 92
    jne .separator
    add rdi, 2                   ; filename is replaced with the date

    ; Extended paths: drive C:\ -> \\?\C:\; UNC -> \\?\UNC\server\share.
    mov rbp, rbx
    cmp word [rbx+2], ':'
    jne .unc
    sub rbp, 8
    jmp .prefix
.unc:
    cmp dword [rbx+4], 0x005c003f ; already \\?\...
    je .path_ready
    sub rbp, 12
    mov rax, 0x005c0043004e0055   ; UTF-16 "UNC\"
    mov [rbp+8], rax
.prefix:
    mov rax, 0x005c003f005c005c   ; UTF-16 "\\?\"
    mov [rbp], rax
.path_ready:
    lea rbx, [rsp+32]            ; SYSTEMTIME, separate from API shadow space
%ifdef TEST_YEAR
    ; Test-only deterministic date; absent from all release binaries.
    mov word [rbx], TEST_YEAR
    mov word [rbx+2], TEST_MONTH
    mov word [rbx+6], TEST_DAY
%else
    mov rcx, rbx
    call [__imp_GetLocalTime]     ; take exactly one local date snapshot
%endif
    call format_date
    mov rcx, rbp
    xor edx, edx
    call [__imp_CreateDirectoryW]
    test eax, eax
    jnz .yesterday
    call [__imp_GetLastError]
    cmp eax, 183                 ; ERROR_ALREADY_EXISTS
    jne exit_eax
    mov rcx, rbp
    call [__imp_GetFileAttributesW]
    cmp eax, -1
    je last_error
    test al, 0x10               ; a same-named file is NOT success
    jz exists_error
.yesterday:
    call previous_date
    call format_date
    mov rcx, rbp
    call [__imp_GetFileAttributesW]
    cmp eax, -1
    je remove_error
    ; Preserve files and reparse points (junctions/symlinks).
    and eax, 0x410
    cmp eax, 0x10
    jne success
    mov rcx, rbp
    call [__imp_RemoveDirectoryW] ; atomic empty-directory removal, no recursion
    test eax, eax
    jnz success
remove_error:
    call [__imp_GetLastError]
    cmp eax, 2                   ; ERROR_FILE_NOT_FOUND
    je success
    cmp eax, 3                   ; ERROR_PATH_NOT_FOUND
    je success
    cmp eax, 145                 ; ERROR_DIR_NOT_EMPTY
    je success
    jmp exit_eax
path_error:
    mov eax, 206                 ; ERROR_FILENAME_EXCED_RANGE
    jmp exit_eax
exists_error:
    mov eax, 183
    jmp exit_eax
last_error:
    call [__imp_GetLastError]
    jmp exit_eax
success:
    xor eax, eax
exit_eax:
    mov ecx, eax
    call [__imp_ExitProcess]

%include "calendar.inc"

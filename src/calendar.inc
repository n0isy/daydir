; Gregorian calendar decrement, not a subtraction of 24 hours.
; RBX = SYSTEMTIME. Internal leaf function; preserves RBX/RBP/RDI.
previous_date:
    dec word [rbx+6]
    jnz .done
    dec word [rbx+2]
    jnz .month
    mov word [rbx+2], 12
    dec word [rbx]
.month:
    movzx ecx, word [rbx+2]
    lea rdx, [month_days-1]
    movzx ecx, byte [rdx+rcx]
    cmp word [rbx+2], 2
    jne .set_day
    movzx eax, word [rbx]
    test al, 3
    jnz .set_day
    ; Divisible by 4; century years are leap only if divisible by 400.
    xor edx, edx
    mov esi, 100
    div esi
    test edx, edx
    jnz .leap
    test al, 3                   ; (year / 100) mod 4
    jnz .set_day
.leap:
    inc ecx
.set_day:
    mov [rbx+6], cx
.done:
    ret

; Format exactly 10 UTF-16 characters plus NUL, no printf/wsprintf import.
; RDI = destination; RBX = SYSTEMTIME. Preserves both and RBP.
format_date:
    movzx eax, word [rbx]
    lea r8, [rdi+6]
    mov ecx, 4
    call digits
    mov word [rdi+8], '_'
    movzx eax, word [rbx+2]
    lea r8, [rdi+12]
    mov cl, 2
    call digits
    mov word [rdi+14], '_'
    movzx eax, word [rbx+6]
    lea r8, [rdi+18]
    mov cl, 2
    call digits
    mov word [rdi+20], 0
    ret
digits:
    mov r9d, 10
.digit:
    xor edx, edx
    div r9d
    add dl, '0'
    mov [r8], dx
    sub r8, 2
    loop .digit
    ret

month_days: db 31,28,31,30,31,30,31,31,30,31,30,31

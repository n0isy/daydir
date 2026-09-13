; SysV wrapper around the exact production calendar/formatting instructions.
bits 64
default rel
global calendar_test
section .text
calendar_test:
    push rbx
    mov rbx, rdi                 ; SYSTEMTIME pointer
    mov rdi, rsi                 ; UTF-16 output pointer
    call previous_date
    call format_date
    pop rbx
    ret
%include "calendar.inc"
section .note.GNU-stack noalloc noexec nowrite progbits

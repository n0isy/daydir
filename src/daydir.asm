; daydir: a Windows x64 executable assembled directly as a PE32+ image.
; NASM emits the headers, code and imports without an external linker.
bits 64
org 0
%ifdef MAP_FILE
[map symbols MAP_FILE]
%endif
%define ALIGNMENT 4
%define ROUND(x) (((x) + ALIGNMENT - 1) & ~(ALIGNMENT - 1))

db 'MZ'
times 0x3c-($-$$) db 0
dd pe                           ; e_lfanew: PE signature offset
pe:
db 'PE', 0, 0
dw 0x8664, 1                    ; AMD64, one section
dd 0, 0, 0                      ; timestamp, symbol-table offset and count
dw optional_end-optional        ; SizeOfOptionalHeader
dw 0x23                         ; executable, large-address-aware, relocs stripped
optional:
dw 0x20b                        ; PE32+
db 0, 0                         ; linker version (not used)
dd image_end-code, 0, 0          ; code, initialized data, uninitialized data sizes
dd start, code                  ; entry point and base of code, both RVAs
dq 0x140000000                  ; preferred ImageBase
dd ALIGNMENT, ALIGNMENT          ; SectionAlignment, FileAlignment
dw 6, 0, 0, 0, 6, 0             ; OS 6.0, image 0.0, subsystem 6.0
dd 0                            ; reserved Win32VersionValue
dd image_end, code, 0            ; SizeOfImage, SizeOfHeaders, CheckSum
dw 2, 0x100                     ; GUI subsystem, NX-compatible
dq 1048576, 131072               ; stack reserve and commit, in bytes
dq 1048576, 4096                 ; heap reserve and commit, in bytes
dd 0, 2                         ; export and import directory slots
dd 0, 0                         ; empty export directory
dd imports, 40                  ; import directory RVA and size
optional_end:
db '.text', 0, 0, 0
dd image_end-code, code          ; VirtualSize, VirtualAddress
dd image_end-code, code          ; SizeOfRawData, PointerToRawData
dd 0, 0                         ; relocation and line-number file offsets
dw 0, 0                         ; relocation and line-number counts
dd 0x60000020                   ; code / read / execute
times ROUND($-$$)-($-$$) db 0
code:
%include "program.inc"

align 4, db 0
imports:
dd 0, 0, 0, dll_name, iat        ; no separate ILT: loader uses IAT for lookup
times 20 db 0
align 8, db 0
iat:
%macro api_slot 1
__imp_%1: dq name_%1
%endmacro
api_slot GetModuleFileNameW
api_slot GetLocalTime
api_slot CreateDirectoryW
api_slot RemoveDirectoryW
api_slot GetFileAttributesW
api_slot GetLastError
api_slot ExitProcess
dq 0
%macro api_name 1
align 2, db 0
name_%1: dw 0
db %str(%1), 0
%endmacro
api_name GetModuleFileNameW
api_name GetLocalTime
api_name CreateDirectoryW
api_name RemoveDirectoryW
api_name GetFileAttributesW
api_name GetLastError
api_name ExitProcess
dll_name: db 'KERNEL32.dll', 0
times ROUND($-$$)-($-$$) db 0
image_end:

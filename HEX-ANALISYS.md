# HEX analysis of daydir.exe

File size: **984 bytes**.

Byte layout of the executable assembled from `src/daydir.asm`.
Offsets and inclusive ranges below are hexadecimal. Every byte is assigned exactly once.

## File layout

| Range | Bytes | Contents |
| --- | ---: | --- |
| `0000-003F` | 64 | Minimal DOS header; no executable DOS stub |
| `0040-00FF` | 192 | PE signature, COFF header, optional header, section header |
| `0100-02D1` | 466 | x64 instructions |
| `02D2-02DD` | 12 | Month lengths |
| `02DE-03D7` | 250 | Import metadata and alignment padding |

## Byte accounting

| Category | Bytes | Zero bytes |
| --- | ---: | ---: |
| DOS header | 64 | 61 |
| PE headers | 192 | 147 |
| Machine code | 466 | 95 |
| Constants | 12 | 0 |
| Padding | 9 | 9 |
| Imports | 241 | 108 |
| **Total** | **984** | **420** |

## PE layout and imports

The 64-byte DOS header defines `MZ` and `e_lfanew = 0x40`; the other bytes are zero.
The PE32+ optional header is 128 bytes: 112 fixed bytes and two 8-byte directory slots.
The export directory is empty; the import directory points to `0x2E0`.
One 40-byte section header completes the 256-byte header area without padding or overlap.

The executable uses 4-byte file and section alignment. For this layout, section RVA equals
file offset (`0x100`). The preferred image base is `0x140000000`; the image is fixed and
has no base relocation table. The GUI subsystem avoids a console window. NX compatibility
is declared. The section's declared characteristics are `0x60000020` (code/read/execute).

`OriginalFirstThunk = 0`: the loader uses the IAT at `0x308` as the lookup table as well.
Its seven 8-byte entries initially point to hint/name records; the final 8-byte entry is zero.
The Windows loader replaces the seven entries with actual function addresses. All imports
are by name from KERNEL32.dll. The application does not resolve exports itself.

The 20-byte null import descriptor, 8-byte null IAT entry, 16-bit import hints and string
terminators are structural data. Zero does not mean a byte is removable.

## Padding and zero bytes

There are **420 zero bytes**, of which **9 bytes** are alignment padding.
Total padding is **9 bytes**. All remaining zero bytes belong to fields, operands or terminators.

| Range | Bytes | Fill |
| --- | ---: | --- |
| `02DE–02DF` | 2 | `00 00` |
| `035D–035D` | 1 | `00` |
| `036D–036D` | 1 | `00` |
| `0381–0381` | 1 | `00` |
| `0395–0395` | 1 | `00` |
| `03AB–03AB` | 1 | `00` |
| `03BB–03BB` | 1 | `00` |
| `03D7–03D7` | 1 | `00` |

All headers, raw section bytes and padding declared by this PE are physically present.
There is no unused second lookup table, DOS message, debug data, resource section or
reserved section-header slot. Removing padding in place would invalidate later RVAs.

File size is not process memory usage: the PE reserves 1 MiB of stack and commits 128 KiB
so the program can allocate its long-path buffer without probing uncommitted stack pages.
System DLLs and loader memory are also outside the 984-byte file.

## Every field and instruction

| Range | Bytes | Category / purpose | Hex bytes / value |
| --- | ---: | --- | --- |
| `0000–0001` | 2 | DOS header / e_magic | `4d 5a` / MZ |
| `0002–0003` | 2 | DOS header / e_cblp | `00 00` / 0x0 |
| `0004–0005` | 2 | DOS header / e_cp | `00 00` / 0x0 |
| `0006–0007` | 2 | DOS header / e_crlc | `00 00` / 0x0 |
| `0008–0009` | 2 | DOS header / e_cparhdr | `00 00` / 0x0 |
| `000A–000B` | 2 | DOS header / e_minalloc | `00 00` / 0x0 |
| `000C–000D` | 2 | DOS header / e_maxalloc | `00 00` / 0x0 |
| `000E–000F` | 2 | DOS header / e_ss | `00 00` / 0x0 |
| `0010–0011` | 2 | DOS header / e_sp | `00 00` / 0x0 |
| `0012–0013` | 2 | DOS header / e_csum | `00 00` / 0x0 |
| `0014–0015` | 2 | DOS header / e_ip | `00 00` / 0x0 |
| `0016–0017` | 2 | DOS header / e_cs | `00 00` / 0x0 |
| `0018–0019` | 2 | DOS header / e_lfarlc | `00 00` / 0x0 |
| `001A–001B` | 2 | DOS header / e_ovno | `00 00` / 0x0 |
| `001C–0023` | 8 | DOS header / e_res[4] | `00 00 00 00 00 00 00 00` / 0x0 |
| `0024–0025` | 2 | DOS header / e_oemid | `00 00` / 0x0 |
| `0026–0027` | 2 | DOS header / e_oeminfo | `00 00` / 0x0 |
| `0028–003B` | 20 | DOS header / e_res2[10] | `00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00` / 0x0 |
| `003C–003F` | 4 | DOS header / e_lfanew | `40 00 00 00` / 0x40 |
| `0040–0043` | 4 | PE headers / Signature | `50 45 00 00` / PE\0\0 |
| `0044–0045` | 2 | PE headers / Machine (AMD64) | `64 86` / 0x8664 |
| `0046–0047` | 2 | PE headers / NumberOfSections | `01 00` / 0x1 |
| `0048–004B` | 4 | PE headers / TimeDateStamp | `00 00 00 00` / 0x0 |
| `004C–004F` | 4 | PE headers / PointerToSymbolTable | `00 00 00 00` / 0x0 |
| `0050–0053` | 4 | PE headers / NumberOfSymbols | `00 00 00 00` / 0x0 |
| `0054–0055` | 2 | PE headers / SizeOfOptionalHeader | `80 00` / 0x80 |
| `0056–0057` | 2 | PE headers / Characteristics | `23 00` / 0x23 |
| `0058–0059` | 2 | PE headers / Magic (PE32+) | `0b 02` / 0x20b |
| `005A–005A` | 1 | PE headers / MajorLinkerVersion | `00` / 0x0 |
| `005B–005B` | 1 | PE headers / MinorLinkerVersion | `00` / 0x0 |
| `005C–005F` | 4 | PE headers / SizeOfCode | `d8 02 00 00` / 0x2d8 |
| `0060–0063` | 4 | PE headers / SizeOfInitializedData | `00 00 00 00` / 0x0 |
| `0064–0067` | 4 | PE headers / SizeOfUninitializedData | `00 00 00 00` / 0x0 |
| `0068–006B` | 4 | PE headers / AddressOfEntryPoint | `00 01 00 00` / 0x100 |
| `006C–006F` | 4 | PE headers / BaseOfCode | `00 01 00 00` / 0x100 |
| `0070–0077` | 8 | PE headers / ImageBase | `00 00 00 40 01 00 00 00` / 0x140000000 |
| `0078–007B` | 4 | PE headers / SectionAlignment | `04 00 00 00` / 0x4 |
| `007C–007F` | 4 | PE headers / FileAlignment | `04 00 00 00` / 0x4 |
| `0080–0081` | 2 | PE headers / MajorOperatingSystemVersion | `06 00` / 0x6 |
| `0082–0083` | 2 | PE headers / MinorOperatingSystemVersion | `00 00` / 0x0 |
| `0084–0085` | 2 | PE headers / MajorImageVersion | `00 00` / 0x0 |
| `0086–0087` | 2 | PE headers / MinorImageVersion | `00 00` / 0x0 |
| `0088–0089` | 2 | PE headers / MajorSubsystemVersion | `06 00` / 0x6 |
| `008A–008B` | 2 | PE headers / MinorSubsystemVersion | `00 00` / 0x0 |
| `008C–008F` | 4 | PE headers / Win32VersionValue | `00 00 00 00` / 0x0 |
| `0090–0093` | 4 | PE headers / SizeOfImage | `d8 03 00 00` / 0x3d8 |
| `0094–0097` | 4 | PE headers / SizeOfHeaders | `00 01 00 00` / 0x100 |
| `0098–009B` | 4 | PE headers / CheckSum | `00 00 00 00` / 0x0 |
| `009C–009D` | 2 | PE headers / Subsystem | `02 00` / 0x2 |
| `009E–009F` | 2 | PE headers / DllCharacteristics | `00 01` / 0x100 |
| `00A0–00A7` | 8 | PE headers / SizeOfStackReserve | `00 00 10 00 00 00 00 00` / 0x100000 |
| `00A8–00AF` | 8 | PE headers / SizeOfStackCommit | `00 00 02 00 00 00 00 00` / 0x20000 |
| `00B0–00B7` | 8 | PE headers / SizeOfHeapReserve | `00 00 10 00 00 00 00 00` / 0x100000 |
| `00B8–00BF` | 8 | PE headers / SizeOfHeapCommit | `00 10 00 00 00 00 00 00` / 0x1000 |
| `00C0–00C3` | 4 | PE headers / LoaderFlags | `00 00 00 00` / 0x0 |
| `00C4–00C7` | 4 | PE headers / NumberOfRvaAndSizes | `02 00 00 00` / 0x2 |
| `00C8–00CB` | 4 | PE headers / Export directory: RVA | `00 00 00 00` / 0x0 |
| `00CC–00CF` | 4 | PE headers / Export directory: size | `00 00 00 00` / 0x0 |
| `00D0–00D3` | 4 | PE headers / Import directory: RVA | `e0 02 00 00` / 0x2e0 |
| `00D4–00D7` | 4 | PE headers / Import directory: size | `28 00 00 00` / 0x28 |
| `00D8–00DF` | 8 | PE headers / Section.Name | `2e 74 65 78 74 00 00 00` / .text |
| `00E0–00E3` | 4 | PE headers / VirtualSize | `d8 02 00 00` / 0x2d8 |
| `00E4–00E7` | 4 | PE headers / VirtualAddress | `00 01 00 00` / 0x100 |
| `00E8–00EB` | 4 | PE headers / SizeOfRawData | `d8 02 00 00` / 0x2d8 |
| `00EC–00EF` | 4 | PE headers / PointerToRawData | `00 01 00 00` / 0x100 |
| `00F0–00F3` | 4 | PE headers / PointerToRelocations | `00 00 00 00` / 0x0 |
| `00F4–00F7` | 4 | PE headers / PointerToLinenumbers | `00 00 00 00` / 0x0 |
| `00F8–00F9` | 2 | PE headers / NumberOfRelocations | `00 00` / 0x0 |
| `00FA–00FB` | 2 | PE headers / NumberOfLinenumbers | `00 00` / 0x0 |
| `00FC–00FF` | 4 | PE headers / Section.Characteristics | `20 00 00 60` / 0x60000020 |
| `0100–0106` | 7 | Machine code / start: sub rsp,0x10038 | `48 81 ec 38 00 01 00` |
| `0107–010B` | 5 | Machine code / start: lea rbx,[rsp+0x40] | `48 8d 5c 24 40` |
| `010C–010D` | 2 | Machine code / start: xor ecx,ecx | `31 c9` |
| `010E–0110` | 3 | Machine code / start: mov rdx,rbx | `48 89 da` |
| `0111–0116` | 6 | Machine code / start: mov r8d,0x7fee | `41 b8 ee 7f 00 00` |
| `0117–011C` | 6 | Machine code / start: call [rel 0x308] | `ff 15 eb 01 00 00` |
| `011D–011E` | 2 | Machine code / start: test eax,eax | `85 c0` |
| `011F–0124` | 6 | Machine code / start: jz near 0x21b | `0f 84 f6 00 00 00` |
| `0125–0129` | 5 | Machine code / start: cmp eax,0x7fee | `3d ee 7f 00 00` |
| `012A–012F` | 6 | Machine code / start: jnc near 0x20d | `0f 83 dd 00 00 00` |
| `0130–0133` | 4 | Machine code / start: lea rdi,[rbx+rax*2] | `48 8d 3c 43` |
| `0134–0136` | 3 | Machine code / start: cmp rdi,rbx | `48 39 df` |
| `0137–013C` | 6 | Machine code / start: jz near 0x20d | `0f 84 d0 00 00 00` |
| `013D–0140` | 4 | Machine code / start: sub rdi,byte +0x2 | `48 83 ef 02` |
| `0141–0144` | 4 | Machine code / start: cmp word [rdi],byte +0x5c | `66 83 3f 5c` |
| `0145–0146` | 2 | Machine code / start: jnz 0x134 | `75 ed` |
| `0147–014A` | 4 | Machine code / start: add rdi,byte +0x2 | `48 83 c7 02` |
| `014B–014D` | 3 | Machine code / start: mov rbp,rbx | `48 89 dd` |
| `014E–0152` | 5 | Machine code / start: cmp word [rbx+0x2],byte +0x3a | `66 83 7b 02 3a` |
| `0153–0154` | 2 | Machine code / start: jnz 0x15b | `75 06` |
| `0155–0158` | 4 | Machine code / start: sub rbp,byte +0x8 | `48 83 ed 08` |
| `0159–015A` | 2 | Machine code / start: jmp short 0x176 | `eb 1b` |
| `015B–0161` | 7 | Machine code / start: cmp dword [rbx+0x4],0x5c003f | `81 7b 04 3f 00 5c 00` |
| `0162–0163` | 2 | Machine code / start: jz 0x184 | `74 20` |
| `0164–0167` | 4 | Machine code / start: sub rbp,byte +0xc | `48 83 ed 0c` |
| `0168–0171` | 10 | Machine code / start: mov rax,0x5c0043004e0055 | `48 b8 55 00 4e 00 43 00 5c 00` |
| `0172–0175` | 4 | Machine code / start: mov [rbp+0x8],rax | `48 89 45 08` |
| `0176–017F` | 10 | Machine code / start: mov rax,0x5c003f005c005c | `48 b8 5c 00 5c 00 3f 00 5c 00` |
| `0180–0183` | 4 | Machine code / start: mov [rbp+0x0],rax | `48 89 45 00` |
| `0184–0188` | 5 | Machine code / start: lea rbx,[rsp+0x20] | `48 8d 5c 24 20` |
| `0189–018B` | 3 | Machine code / start: mov rcx,rbx | `48 89 d9` |
| `018C–0191` | 6 | Machine code / start: call [rel 0x310] | `ff 15 7e 01 00 00` |
| `0192–0196` | 5 | Machine code / start: call 0x277 | `e8 e0 00 00 00` |
| `0197–0199` | 3 | Machine code / start: mov rcx,rbp | `48 89 e9` |
| `019A–019B` | 2 | Machine code / start: xor edx,edx | `31 d2` |
| `019C–01A1` | 6 | Machine code / start: call [rel 0x318] | `ff 15 76 01 00 00` |
| `01A2–01A3` | 2 | Machine code / start: test eax,eax | `85 c0` |
| `01A4–01A5` | 2 | Machine code / start: jnz 0x1c5 | `75 1f` |
| `01A6–01AB` | 6 | Machine code / start: call [rel 0x330] | `ff 15 84 01 00 00` |
| `01AC–01B0` | 5 | Machine code / start: cmp eax,0xb7 | `3d b7 00 00 00` |
| `01B1–01B2` | 2 | Machine code / start: jnz 0x225 | `75 72` |
| `01B3–01B5` | 3 | Machine code / start: mov rcx,rbp | `48 89 e9` |
| `01B6–01BB` | 6 | Machine code / start: call [rel 0x328] | `ff 15 6c 01 00 00` |
| `01BC–01BE` | 3 | Machine code / start: cmp eax,byte -0x1 | `83 f8 ff` |
| `01BF–01C0` | 2 | Machine code / start: jz 0x21b | `74 5a` |
| `01C1–01C2` | 2 | Machine code / start: test al,0x10 | `a8 10` |
| `01C3–01C4` | 2 | Machine code / start: jz 0x214 | `74 4f` |
| `01C5–01C9` | 5 | Machine code / start: call 0x22d | `e8 63 00 00 00` |
| `01CA–01CE` | 5 | Machine code / start: call 0x277 | `e8 a8 00 00 00` |
| `01CF–01D1` | 3 | Machine code / start: mov rcx,rbp | `48 89 e9` |
| `01D2–01D7` | 6 | Machine code / start: call [rel 0x328] | `ff 15 50 01 00 00` |
| `01D8–01DA` | 3 | Machine code / start: cmp eax,byte -0x1 | `83 f8 ff` |
| `01DB–01DC` | 2 | Machine code / start: jz 0x1f4 | `74 17` |
| `01DD–01E1` | 5 | Machine code / start: and eax,0x410 | `25 10 04 00 00` |
| `01E2–01E4` | 3 | Machine code / start: cmp eax,byte +0x10 | `83 f8 10` |
| `01E5–01E6` | 2 | Machine code / start: jnz 0x223 | `75 3c` |
| `01E7–01E9` | 3 | Machine code / start: mov rcx,rbp | `48 89 e9` |
| `01EA–01EF` | 6 | Machine code / start: call [rel 0x320] | `ff 15 30 01 00 00` |
| `01F0–01F1` | 2 | Machine code / start: test eax,eax | `85 c0` |
| `01F2–01F3` | 2 | Machine code / start: jnz 0x223 | `75 2f` |
| `01F4–01F9` | 6 | Machine code / start: call [rel 0x330] | `ff 15 36 01 00 00` |
| `01FA–01FC` | 3 | Machine code / start: cmp eax,byte +0x2 | `83 f8 02` |
| `01FD–01FE` | 2 | Machine code / start: jz 0x223 | `74 24` |
| `01FF–0201` | 3 | Machine code / start: cmp eax,byte +0x3 | `83 f8 03` |
| `0202–0203` | 2 | Machine code / start: jz 0x223 | `74 1f` |
| `0204–0208` | 5 | Machine code / start: cmp eax,0x91 | `3d 91 00 00 00` |
| `0209–020A` | 2 | Machine code / start: jz 0x223 | `74 18` |
| `020B–020C` | 2 | Machine code / start: jmp short 0x225 | `eb 18` |
| `020D–0211` | 5 | Machine code / start: mov eax,0xce | `b8 ce 00 00 00` |
| `0212–0213` | 2 | Machine code / start: jmp short 0x225 | `eb 11` |
| `0214–0218` | 5 | Machine code / start: mov eax,0xb7 | `b8 b7 00 00 00` |
| `0219–021A` | 2 | Machine code / start: jmp short 0x225 | `eb 0a` |
| `021B–0220` | 6 | Machine code / start: call [rel 0x330] | `ff 15 0f 01 00 00` |
| `0221–0222` | 2 | Machine code / start: jmp short 0x225 | `eb 02` |
| `0223–0224` | 2 | Machine code / start: xor eax,eax | `31 c0` |
| `0225–0226` | 2 | Machine code / start: mov ecx,eax | `89 c1` |
| `0227–022C` | 6 | Machine code / start: call [rel 0x338] | `ff 15 0b 01 00 00` |
| `022D–0230` | 4 | Machine code / previous_date: dec word [rbx+0x6] | `66 ff 4b 06` |
| `0231–0232` | 2 | Machine code / previous_date: jnz 0x276 | `75 43` |
| `0233–0236` | 4 | Machine code / previous_date: dec word [rbx+0x2] | `66 ff 4b 02` |
| `0237–0238` | 2 | Machine code / previous_date: jnz 0x242 | `75 09` |
| `0239–023E` | 6 | Machine code / previous_date: mov word [rbx+0x2],0xc | `66 c7 43 02 0c 00` |
| `023F–0241` | 3 | Machine code / previous_date: dec word [rbx] | `66 ff 0b` |
| `0242–0245` | 4 | Machine code / previous_date: movzx ecx,word [rbx+0x2] | `0f b7 4b 02` |
| `0246–024C` | 7 | Machine code / previous_date: lea rdx,[rel 0x2d1] | `48 8d 15 84 00 00 00` |
| `024D–0250` | 4 | Machine code / previous_date: movzx ecx,byte [rdx+rcx] | `0f b6 0c 0a` |
| `0251–0255` | 5 | Machine code / previous_date: cmp word [rbx+0x2],byte +0x2 | `66 83 7b 02 02` |
| `0256–0257` | 2 | Machine code / previous_date: jnz 0x272 | `75 1a` |
| `0258–025A` | 3 | Machine code / previous_date: movzx eax,word [rbx] | `0f b7 03` |
| `025B–025C` | 2 | Machine code / previous_date: test al,0x3 | `a8 03` |
| `025D–025E` | 2 | Machine code / previous_date: jnz 0x272 | `75 13` |
| `025F–0260` | 2 | Machine code / previous_date: xor edx,edx | `31 d2` |
| `0261–0265` | 5 | Machine code / previous_date: mov esi,0x64 | `be 64 00 00 00` |
| `0266–0267` | 2 | Machine code / previous_date: div esi | `f7 f6` |
| `0268–0269` | 2 | Machine code / previous_date: test edx,edx | `85 d2` |
| `026A–026B` | 2 | Machine code / previous_date: jnz 0x270 | `75 04` |
| `026C–026D` | 2 | Machine code / previous_date: test al,0x3 | `a8 03` |
| `026E–026F` | 2 | Machine code / previous_date: jnz 0x272 | `75 02` |
| `0270–0271` | 2 | Machine code / previous_date: inc ecx | `ff c1` |
| `0272–0275` | 4 | Machine code / previous_date: mov [rbx+0x6],cx | `66 89 4b 06` |
| `0276–0276` | 1 | Machine code / previous_date: ret | `c3` |
| `0277–0279` | 3 | Machine code / format_date: movzx eax,word [rbx] | `0f b7 03` |
| `027A–027D` | 4 | Machine code / format_date: lea r8,[rdi+0x6] | `4c 8d 47 06` |
| `027E–0282` | 5 | Machine code / format_date: mov ecx,0x4 | `b9 04 00 00 00` |
| `0283–0287` | 5 | Machine code / format_date: call 0x2b9 | `e8 31 00 00 00` |
| `0288–028D` | 6 | Machine code / format_date: mov word [rdi+0x8],0x5f | `66 c7 47 08 5f 00` |
| `028E–0291` | 4 | Machine code / format_date: movzx eax,word [rbx+0x2] | `0f b7 43 02` |
| `0292–0295` | 4 | Machine code / format_date: lea r8,[rdi+0xc] | `4c 8d 47 0c` |
| `0296–0297` | 2 | Machine code / format_date: mov cl,0x2 | `b1 02` |
| `0298–029C` | 5 | Machine code / format_date: call 0x2b9 | `e8 1c 00 00 00` |
| `029D–02A2` | 6 | Machine code / format_date: mov word [rdi+0xe],0x5f | `66 c7 47 0e 5f 00` |
| `02A3–02A6` | 4 | Machine code / format_date: movzx eax,word [rbx+0x6] | `0f b7 43 06` |
| `02A7–02AA` | 4 | Machine code / format_date: lea r8,[rdi+0x12] | `4c 8d 47 12` |
| `02AB–02AC` | 2 | Machine code / format_date: mov cl,0x2 | `b1 02` |
| `02AD–02B1` | 5 | Machine code / format_date: call 0x2b9 | `e8 07 00 00 00` |
| `02B2–02B7` | 6 | Machine code / format_date: mov word [rdi+0x14],0x0 | `66 c7 47 14 00 00` |
| `02B8–02B8` | 1 | Machine code / format_date: ret | `c3` |
| `02B9–02BE` | 6 | Machine code / digits: mov r9d,0xa | `41 b9 0a 00 00 00` |
| `02BF–02C0` | 2 | Machine code / digits: xor edx,edx | `31 d2` |
| `02C1–02C3` | 3 | Machine code / digits: div r9d | `41 f7 f1` |
| `02C4–02C6` | 3 | Machine code / digits: add dl,0x30 | `80 c2 30` |
| `02C7–02CA` | 4 | Machine code / digits: mov [r8],dx | `66 41 89 10` |
| `02CB–02CE` | 4 | Machine code / digits: sub r8,byte +0x2 | `49 83 e8 02` |
| `02CF–02D0` | 2 | Machine code / digits: loop 0x2bf | `e2 ee` |
| `02D1–02D1` | 1 | Machine code / digits: ret | `c3` |
| `02D2–02DD` | 12 | Constants / month_days | `1f 1c 1f 1e 1f 1e 1f 1f 1e 1f 1e 1f` / 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 |
| `02DE–02DF` | 2 | Padding / Alignment fill | `00 00` / 00 00 |
| `02E0–02E3` | 4 | Imports / Import descriptor: OriginalFirstThunk (zero: use IAT) | `00 00 00 00` / 0x0 |
| `02E4–02E7` | 4 | Imports / Import descriptor: TimeDateStamp | `00 00 00 00` / 0x0 |
| `02E8–02EB` | 4 | Imports / Import descriptor: ForwarderChain | `00 00 00 00` / 0x0 |
| `02EC–02EF` | 4 | Imports / Import descriptor: Name (DLL) | `ca 03 00 00` / 0x3ca |
| `02F0–02F3` | 4 | Imports / Import descriptor: FirstThunk (IAT) | `08 03 00 00` / 0x308 |
| `02F4–0307` | 20 | Imports / End of import descriptor list | `00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00` / 20 mandatory zero bytes |
| `0308–030F` | 8 | Imports / Shared IAT / lookup[0] -&gt; GetModuleFileNameW | `48 03 00 00 00 00 00 00` / 0x348 |
| `0310–0317` | 8 | Imports / Shared IAT / lookup[1] -&gt; GetLocalTime | `5e 03 00 00 00 00 00 00` / 0x35e |
| `0318–031F` | 8 | Imports / Shared IAT / lookup[2] -&gt; CreateDirectoryW | `6e 03 00 00 00 00 00 00` / 0x36e |
| `0320–0327` | 8 | Imports / Shared IAT / lookup[3] -&gt; RemoveDirectoryW | `82 03 00 00 00 00 00 00` / 0x382 |
| `0328–032F` | 8 | Imports / Shared IAT / lookup[4] -&gt; GetFileAttributesW | `96 03 00 00 00 00 00 00` / 0x396 |
| `0330–0337` | 8 | Imports / Shared IAT / lookup[5] -&gt; GetLastError | `ac 03 00 00 00 00 00 00` / 0x3ac |
| `0338–033F` | 8 | Imports / Shared IAT / lookup[6] -&gt; ExitProcess | `bc 03 00 00 00 00 00 00` / 0x3bc |
| `0340–0347` | 8 | Imports / Shared IAT / lookup terminator | `00 00 00 00 00 00 00 00` / 0x0 |
| `0348–0349` | 2 | Imports / GetModuleFileNameW: hint | `00 00` / 0x0 |
| `034A–035B` | 18 | Imports / API name | `47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 57` / GetModuleFileNameW |
| `035C–035C` | 1 | Imports / GetModuleFileNameW: NUL terminator | `00` / 0x0 |
| `035D–035D` | 1 | Padding / Alignment fill | `00` / 00 |
| `035E–035F` | 2 | Imports / GetLocalTime: hint | `00 00` / 0x0 |
| `0360–036B` | 12 | Imports / API name | `47 65 74 4c 6f 63 61 6c 54 69 6d 65` / GetLocalTime |
| `036C–036C` | 1 | Imports / GetLocalTime: NUL terminator | `00` / 0x0 |
| `036D–036D` | 1 | Padding / Alignment fill | `00` / 00 |
| `036E–036F` | 2 | Imports / CreateDirectoryW: hint | `00 00` / 0x0 |
| `0370–037F` | 16 | Imports / API name | `43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 57` / CreateDirectoryW |
| `0380–0380` | 1 | Imports / CreateDirectoryW: NUL terminator | `00` / 0x0 |
| `0381–0381` | 1 | Padding / Alignment fill | `00` / 00 |
| `0382–0383` | 2 | Imports / RemoveDirectoryW: hint | `00 00` / 0x0 |
| `0384–0393` | 16 | Imports / API name | `52 65 6d 6f 76 65 44 69 72 65 63 74 6f 72 79 57` / RemoveDirectoryW |
| `0394–0394` | 1 | Imports / RemoveDirectoryW: NUL terminator | `00` / 0x0 |
| `0395–0395` | 1 | Padding / Alignment fill | `00` / 00 |
| `0396–0397` | 2 | Imports / GetFileAttributesW: hint | `00 00` / 0x0 |
| `0398–03A9` | 18 | Imports / API name | `47 65 74 46 69 6c 65 41 74 74 72 69 62 75 74 65 73 57` / GetFileAttributesW |
| `03AA–03AA` | 1 | Imports / GetFileAttributesW: NUL terminator | `00` / 0x0 |
| `03AB–03AB` | 1 | Padding / Alignment fill | `00` / 00 |
| `03AC–03AD` | 2 | Imports / GetLastError: hint | `00 00` / 0x0 |
| `03AE–03B9` | 12 | Imports / API name | `47 65 74 4c 61 73 74 45 72 72 6f 72` / GetLastError |
| `03BA–03BA` | 1 | Imports / GetLastError: NUL terminator | `00` / 0x0 |
| `03BB–03BB` | 1 | Padding / Alignment fill | `00` / 00 |
| `03BC–03BD` | 2 | Imports / ExitProcess: hint | `00 00` / 0x0 |
| `03BE–03C8` | 11 | Imports / API name | `45 78 69 74 50 72 6f 63 65 73 73` / ExitProcess |
| `03C9–03C9` | 1 | Imports / ExitProcess: NUL terminator | `00` / 0x0 |
| `03CA–03D5` | 12 | Imports / DLL name | `4b 45 52 4e 45 4c 33 32 2e 64 6c 6c` / KERNEL32.dll |
| `03D6–03D6` | 1 | Imports / DLL name: NUL terminator | `00` / 0x0 |
| `03D7–03D7` | 1 | Padding / Alignment fill | `00` / 00 |

## Full hex dump

```text
0000  4d 5a 00 00 00 00 00 00 00 00 00 00 00 00 00 00  MZ..............
0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0030  00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00  ............@...
0040  50 45 00 00 64 86 01 00 00 00 00 00 00 00 00 00  PE..d...........
0050  00 00 00 00 80 00 23 00 0b 02 00 00 d8 02 00 00  ......#.........
0060  00 00 00 00 00 00 00 00 00 01 00 00 00 01 00 00  ................
0070  00 00 00 40 01 00 00 00 04 00 00 00 04 00 00 00  ...@............
0080  06 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00  ................
0090  d8 03 00 00 00 01 00 00 00 00 00 00 02 00 00 01  ................
00A0  00 00 10 00 00 00 00 00 00 00 02 00 00 00 00 00  ................
00B0  00 00 10 00 00 00 00 00 00 10 00 00 00 00 00 00  ................
00C0  00 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00  ................
00D0  e0 02 00 00 28 00 00 00 2e 74 65 78 74 00 00 00  ....(....text...
00E0  d8 02 00 00 00 01 00 00 d8 02 00 00 00 01 00 00  ................
00F0  00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60  ............ ..`
0100  48 81 ec 38 00 01 00 48 8d 5c 24 40 31 c9 48 89  H..8...H.\$@1.H.
0110  da 41 b8 ee 7f 00 00 ff 15 eb 01 00 00 85 c0 0f  .A..............
0120  84 f6 00 00 00 3d ee 7f 00 00 0f 83 dd 00 00 00  .....=..........
0130  48 8d 3c 43 48 39 df 0f 84 d0 00 00 00 48 83 ef  H.<CH9.......H..
0140  02 66 83 3f 5c 75 ed 48 83 c7 02 48 89 dd 66 83  .f.?\u.H...H..f.
0150  7b 02 3a 75 06 48 83 ed 08 eb 1b 81 7b 04 3f 00  {.:u.H......{.?.
0160  5c 00 74 20 48 83 ed 0c 48 b8 55 00 4e 00 43 00  \.t H...H.U.N.C.
0170  5c 00 48 89 45 08 48 b8 5c 00 5c 00 3f 00 5c 00  \.H.E.H.\.\.?.\.
0180  48 89 45 00 48 8d 5c 24 20 48 89 d9 ff 15 7e 01  H.E.H.\$ H....~.
0190  00 00 e8 e0 00 00 00 48 89 e9 31 d2 ff 15 76 01  .......H..1...v.
01A0  00 00 85 c0 75 1f ff 15 84 01 00 00 3d b7 00 00  ....u.......=...
01B0  00 75 72 48 89 e9 ff 15 6c 01 00 00 83 f8 ff 74  .urH....l......t
01C0  5a a8 10 74 4f e8 63 00 00 00 e8 a8 00 00 00 48  Z..tO.c........H
01D0  89 e9 ff 15 50 01 00 00 83 f8 ff 74 17 25 10 04  ....P......t.%..
01E0  00 00 83 f8 10 75 3c 48 89 e9 ff 15 30 01 00 00  .....u<H....0...
01F0  85 c0 75 2f ff 15 36 01 00 00 83 f8 02 74 24 83  ..u/..6......t$.
0200  f8 03 74 1f 3d 91 00 00 00 74 18 eb 18 b8 ce 00  ..t.=....t......
0210  00 00 eb 11 b8 b7 00 00 00 eb 0a ff 15 0f 01 00  ................
0220  00 eb 02 31 c0 89 c1 ff 15 0b 01 00 00 66 ff 4b  ...1.........f.K
0230  06 75 43 66 ff 4b 02 75 09 66 c7 43 02 0c 00 66  .uCf.K.u.f.C...f
0240  ff 0b 0f b7 4b 02 48 8d 15 84 00 00 00 0f b6 0c  ....K.H.........
0250  0a 66 83 7b 02 02 75 1a 0f b7 03 a8 03 75 13 31  .f.{..u......u.1
0260  d2 be 64 00 00 00 f7 f6 85 d2 75 04 a8 03 75 02  ..d.......u...u.
0270  ff c1 66 89 4b 06 c3 0f b7 03 4c 8d 47 06 b9 04  ..f.K.....L.G...
0280  00 00 00 e8 31 00 00 00 66 c7 47 08 5f 00 0f b7  ....1...f.G._...
0290  43 02 4c 8d 47 0c b1 02 e8 1c 00 00 00 66 c7 47  C.L.G........f.G
02A0  0e 5f 00 0f b7 43 06 4c 8d 47 12 b1 02 e8 07 00  ._...C.L.G......
02B0  00 00 66 c7 47 14 00 00 c3 41 b9 0a 00 00 00 31  ..f.G....A.....1
02C0  d2 41 f7 f1 80 c2 30 66 41 89 10 49 83 e8 02 e2  .A....0fA..I....
02D0  ee c3 1f 1c 1f 1e 1f 1e 1f 1f 1e 1f 1e 1f 00 00  ................
02E0  00 00 00 00 00 00 00 00 00 00 00 00 ca 03 00 00  ................
02F0  08 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
0300  00 00 00 00 00 00 00 00 48 03 00 00 00 00 00 00  ........H.......
0310  5e 03 00 00 00 00 00 00 6e 03 00 00 00 00 00 00  ^.......n.......
0320  82 03 00 00 00 00 00 00 96 03 00 00 00 00 00 00  ................
0330  ac 03 00 00 00 00 00 00 bc 03 00 00 00 00 00 00  ................
0340  00 00 00 00 00 00 00 00 00 00 47 65 74 4d 6f 64  ..........GetMod
0350  75 6c 65 46 69 6c 65 4e 61 6d 65 57 00 00 00 00  uleFileNameW....
0360  47 65 74 4c 6f 63 61 6c 54 69 6d 65 00 00 00 00  GetLocalTime....
0370  43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 57  CreateDirectoryW
0380  00 00 00 00 52 65 6d 6f 76 65 44 69 72 65 63 74  ....RemoveDirect
0390  6f 72 79 57 00 00 00 00 47 65 74 46 69 6c 65 41  oryW....GetFileA
03A0  74 74 72 69 62 75 74 65 73 57 00 00 00 00 47 65  ttributesW....Ge
03B0  74 4c 61 73 74 45 72 72 6f 72 00 00 00 00 45 78  tLastError....Ex
03C0  69 74 50 72 6f 63 65 73 73 00 4b 45 52 4e 45 4c  itProcess.KERNEL
03D0  33 32 2e 64 6c 6c 00 00                          32.dll..
```

References: [Microsoft PE/COFF](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format),
[NASM flat binary output](https://www.nasm.us/doc/nasm09.html#section-9.1).

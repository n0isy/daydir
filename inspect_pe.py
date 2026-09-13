#!/usr/bin/env python3
"""Account for every byte of daydir.exe; produce Markdown and a per-byte CSV."""
from pathlib import Path
from collections import Counter
import csv
import hashlib
import re
import os
import struct
import subprocess

ROOT = Path(__file__).resolve().parent
EXE = ROOT / "dist/daydir.exe"
data = EXE.read_bytes()
u16 = lambda p: struct.unpack_from("<H", data, p)[0]
u32 = lambda p: struct.unpack_from("<I", data, p)[0]
u64 = lambda p: struct.unpack_from("<Q", data, p)[0]
pe = u32(60)
opt = pe + 24
sh = opt + u16(pe+20)
image_base = u64(opt+24)
raw, rva, virtual_size = u32(sh+20), u32(sh+12), u32(sh+8)
assert raw == rva, "this report expects the low-alignment release"
rows = []

def add(start, size, category, name, value=""):
    assert size > 0 and 0 <= start < start+size <= len(data)
    rows.append(dict(start=start, end=start+size, size=size, category=category,
                     name=name, value=value))

def field(start, size, category, name, value=None):
    if value is None:
        value = f"0x{int.from_bytes(data[start:start+size], 'little'):x}"
    add(start, size, category, name, value)

def string(start):
    end = data.index(0, start)
    return data[start:end].decode("ascii"), end-start

def label_values():
    text = (ROOT / "build/daydir.map").read_text()
    labels = {}
    for match in re.finditer(r"^\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\S+)\s*$", text, re.M):
        labels[int(match[1], 16)] = match[3]
    assert labels[raw] == "start"
    return labels

labels = label_values()

# Full MZ header, including reserved fields.
dos_words = ["e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc", "e_maxalloc",
             "e_ss", "e_sp", "e_csum", "e_ip", "e_cs", "e_lfarlc", "e_ovno"]
for index, name in enumerate(dos_words):
    field(index*2, 2, "DOS header", name, "MZ" if index == 0 else None)
for start, size, name in [(28,8,"e_res[4]"), (36,2,"e_oemid"), (38,2,"e_oeminfo"),
                           (40,20,"e_res2[10]"), (60,4,"e_lfanew")]:
    field(start, size, "DOS header", name)
field(pe, 4, "PE headers", "Signature", "PE\\0\\0")
for offset, size, name in [(4,2,"Machine (AMD64)"), (6,2,"NumberOfSections"),
                          (8,4,"TimeDateStamp"), (12,4,"PointerToSymbolTable"),
                          (16,4,"NumberOfSymbols"), (20,2,"SizeOfOptionalHeader"), (22,2,"Characteristics")]:
    field(pe+offset, size, "PE headers", name)
optional_fields = [
    (0,2,"Magic (PE32+)"), (2,1,"MajorLinkerVersion"), (3,1,"MinorLinkerVersion"),
    (4,4,"SizeOfCode"), (8,4,"SizeOfInitializedData"), (12,4,"SizeOfUninitializedData"),
    (16,4,"AddressOfEntryPoint"), (20,4,"BaseOfCode"), (24,8,"ImageBase"),
    (32,4,"SectionAlignment"), (36,4,"FileAlignment"), (40,2,"MajorOperatingSystemVersion"),
    (42,2,"MinorOperatingSystemVersion"), (44,2,"MajorImageVersion"), (46,2,"MinorImageVersion"),
    (48,2,"MajorSubsystemVersion"), (50,2,"MinorSubsystemVersion"), (52,4,"Win32VersionValue"),
    (56,4,"SizeOfImage"), (60,4,"SizeOfHeaders"), (64,4,"CheckSum"), (68,2,"Subsystem"),
    (70,2,"DllCharacteristics"), (72,8,"SizeOfStackReserve"), (80,8,"SizeOfStackCommit"),
    (88,8,"SizeOfHeapReserve"), (96,8,"SizeOfHeapCommit"), (104,4,"LoaderFlags"), (108,4,"NumberOfRvaAndSizes")]
for offset, size, name in optional_fields:
    field(opt+offset, size, "PE headers", name)
directories = ["Export", "Import"]
assert u32(opt+108) == len(directories)
for index, name in enumerate(directories):
    field(opt+112+index*8, 4, "PE headers", name+" directory: RVA")
    field(opt+116+index*8, 4, "PE headers", name+" directory: size")
for offset, size, name in [(0,8,"Section.Name"), (8,4,"VirtualSize"), (12,4,"VirtualAddress"),
                          (16,4,"SizeOfRawData"), (20,4,"PointerToRawData"), (24,4,"PointerToRelocations"),
                          (28,4,"PointerToLinenumbers"), (32,2,"NumberOfRelocations"),
                          (34,2,"NumberOfLinenumbers"), (36,4,"Section.Characteristics")]:
    field(sh+offset, size, "PE headers", name, ".text" if offset == 0 else None)

# NASM's symbol map marks the boundary between instructions and constants.
month = next(offset for offset, name in labels.items() if name == "month_days")
code_size = month - raw
result = subprocess.run([os.environ.get("NDISASM", "ndisasm"), "-b", "64", "-o", str(raw), "-"],
                        input=data[raw:month], capture_output=True, check=True).stdout.decode("ascii")
instructions = []
for line in result.splitlines():
    match = re.match(r"^([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+(.+)$", line)
    if match:
        instructions.append([int(match[1], 16), bytes.fromhex(match[2]), match[3]])
    else:
        continuation = re.match(r"^\s+-([0-9A-Fa-f]+)\s*$", line)
        assert continuation and instructions, line
        instructions[-1][1] += bytes.fromhex(continuation[1])
function = "start"
for address, binary, instruction in instructions:
    assert data[address:address+len(binary)] == binary
    if labels.get(address) in ("start", "previous_date", "format_date", "digits"):
        function = labels[address]
    add(address, len(binary), "Machine code", f"{function}: {instruction}")
assert sum(row["size"] for row in rows if row["category"] == "Machine code") == code_size

imports = u32(opt+120)
lookup, _, _, dll, iat = struct.unpack_from("<IIIII", data, imports)
assert lookup == 0
for offset, name in enumerate(["OriginalFirstThunk (zero: use IAT)", "TimeDateStamp", "ForwarderChain", "Name (DLL)", "FirstThunk (IAT)"]):
    field(imports+offset*4, 4, "Imports", "Import descriptor: "+name)
add(imports+20, 20, "Imports", "End of import descriptor list", "20 mandatory zero bytes")
index = 0
while True:
    hint_name = u64(iat+index*8)
    if not hint_name:
        field(iat+index*8, 8, "Imports", "Shared IAT / lookup terminator")
        break
    api, length = string(hint_name+2)
    field(iat+index*8, 8, "Imports", f"Shared IAT / lookup[{index}] -> {api}")
    field(hint_name, 2, "Imports", api+": hint")
    add(hint_name+2, length, "Imports", "API name", api)
    field(hint_name+2+length, 1, "Imports", api+": NUL terminator")
    index += 1
dll_name, length = string(dll)
add(dll, length, "Imports", "DLL name", dll_name)
field(dll+length, 1, "Imports", "DLL name: NUL terminator")
month = next(offset for offset, name in labels.items() if name == "month_days")
add(month, 12, "Constants", "month_days", ", ".join(map(str, data[month:month+12])))

# Every remaining byte is alignment fill; fail on overlap or unknown payload.
ordered = sorted(rows, key=lambda row: row["start"])
position = 0
for row in ordered + [dict(start=len(data), end=len(data))]:
    assert row["start"] >= position, "overlapping byte ownership"
    if row["start"] > position:
        gap = data[position:row["start"]]
        assert set(gap) <= {0, 0xcc}, (position, gap)
        add(position, len(gap), "Padding", "Alignment fill", gap.hex(" "))
    position = row["end"]
rows.sort(key=lambda row: row["start"])
assert sum(row["size"] for row in rows) == len(data)
categories = Counter()
zero_categories = Counter()
for row in rows:
    categories[row["category"]] += row["size"]
    zero_categories[row["category"]] += data[row["start"]:row["end"]].count(0)

report_dir = ROOT / "build"
report_dir.mkdir(exist_ok=True)
with (report_dir / "bytes.csv").open("w", newline="", encoding="utf-8-sig") as stream:
    writer = csv.writer(stream)
    writer.writerow(["offset_hex", "offset_decimal", "byte_hex", "category", "field_or_instruction", "byte_in_field"])
    for row in rows:
        for offset in range(row["start"], row["end"]):
            writer.writerow([f"0x{offset:04X}", offset, f"{data[offset]:02X}", row["category"], row["name"], offset-row["start"]])

def bounds(row):
    return f"{row['start']:04X}–{row['end']-1:04X}"

def escaped(text):
    return text.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")

lines = ["# HEX analysis of daydir.exe", "",
         f"File size: **{len(data)} bytes**. SHA-256: `{hashlib.sha256(data).hexdigest()}`.", "",
         "Generated from `dist/daydir.exe` and NASM's symbol map by `python inspect_pe.py`.",
         "Offsets and inclusive ranges below are hexadecimal. Every byte is assigned exactly once.",
         "The generator also writes `build/bytes.csv`: one row for each byte.", "",
         "## File layout", "",
         "| Range | Bytes | Contents |", "| --- | ---: | --- |",
         "| `0000-003F` | 64 | Minimal DOS header; no executable DOS stub |",
         "| `0040-00FF` | 192 | PE signature, COFF header, optional header, section header |",
         "| `0100-02D1` | 466 | x64 instructions |",
         "| `02D2-02DD` | 12 | Month lengths |",
         "| `02DE-03D7` | 250 | Import metadata and alignment padding |", "",
         "## Byte accounting", "",
         "| Category | Bytes | Zero bytes |", "| --- | ---: | ---: |"]
for category in categories:
    lines.append(f"| {category} | {categories[category]} | {zero_categories[category]} |")
lines += [f"| **Total** | **{len(data)}** | **{data.count(0)}** |", "",
          "## PE layout and imports", "",
          "The 64-byte DOS header defines `MZ` and `e_lfanew = 0x40`; the other bytes are zero.",
          "The PE32+ optional header is 128 bytes: 112 fixed bytes and two 8-byte directory slots.",
          "The export directory is empty; the import directory points to `0x2E0`.",
          "One 40-byte section header completes the 256-byte header area without padding or overlap.", "",
          "The executable uses 4-byte file and section alignment. For this layout, section RVA equals",
          "file offset (`0x100`). The preferred image base is `0x140000000`; the image is fixed and",
          "has no base relocation table. The GUI subsystem avoids a console window. NX compatibility",
          "is declared. The section's declared characteristics are `0x60000020` (code/read/execute).", "",
          "`OriginalFirstThunk = 0`: the loader uses the IAT at `0x308` as the lookup table as well.",
          "Its seven 8-byte entries initially point to hint/name records; the final 8-byte entry is zero.",
          "The Windows loader replaces the seven entries with actual function addresses. All imports",
          "are by name from KERNEL32.dll. The application does not resolve exports itself.", "",
          "The 20-byte null import descriptor, 8-byte null IAT entry, 16-bit import hints and string",
          "terminators are structural data. Zero does not mean a byte is removable.", "",
          "## Padding and zero bytes", "",
          f"There are **{data.count(0)} zero bytes**, of which **{zero_categories['Padding']} bytes** are alignment padding.",
          f"Total padding is **{categories['Padding']} bytes**. All remaining zero bytes belong to fields, operands or terminators.", "",
          "| Range | Bytes | Fill |", "| --- | ---: | --- |"]
for row in rows:
    if row["category"] == "Padding":
        lines.append(f"| `{bounds(row)}` | {row['size']} | `{row['value']}` |")
lines += ["", "All headers, raw section bytes and padding declared by this PE are physically present.",
          "There is no unused second lookup table, DOS message, debug data, resource section or",
          "reserved section-header slot. Removing padding in place would invalidate later RVAs.", "",
          "File size is not process memory usage: the PE reserves 1 MiB of stack and commits 128 KiB",
          "so the program can allocate its long-path buffer without probing uncommitted stack pages.",
          "System DLLs and loader memory are also outside the 984-byte file.", "",
          "## Every field and instruction", "",
          "| Range | Bytes | Category / purpose | Hex bytes / value |", "| --- | ---: | --- | --- |"]
for row in rows:
    content = data[row["start"]:row["end"]].hex(" ")
    detail = " / " + escaped(row["value"]) if row["value"] else ""
    lines.append(f"| `{bounds(row)}` | {row['size']} | {escaped(row['category']+' / '+row['name'])} | `{content}`{detail} |")
lines += ["", "## Full hex dump", "", "```text"]
for offset in range(0, len(data), 16):
    chunk = data[offset:offset+16]
    ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
    lines.append(f"{offset:04X}  {chunk.hex(' '):47}  {ascii_part}")
lines += ["```", "", "## Regenerate", "", "```text", "python build.py", "python inspect_pe.py", "```", "",
          "Both NASM and NDISASM are included in the NASM distribution. Python uses only its standard library.", "",
          "References: [Microsoft PE/COFF](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format),",
          "[NASM flat binary output](https://www.nasm.us/doc/nasm09.html#section-9.1).", ""]
(ROOT / "HEX-ANALISYS.md").write_text("\n".join(lines), encoding="utf-8")
print(dict(categories))
print(f"Total zeros: {data.count(0)}; padding zeros: {zero_categories['Padding']}; byte rows: {len(data)}")
print(ROOT / "HEX-ANALISYS.md")

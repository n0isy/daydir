"""Validate the expected hand-built PE and its loader-visible import structure."""
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
APIS = ["GetModuleFileNameW", "GetLocalTime", "CreateDirectoryW", "RemoveDirectoryW",
        "GetFileAttributesW", "GetLastError", "ExitProcess"]

def check_pe(path):
    data = Path(path).read_bytes()
    def u16(offset):
        return struct.unpack_from("<H", data, offset)[0]
    def u32(offset):
        return struct.unpack_from("<I", data, offset)[0]
    def u64(offset):
        return struct.unpack_from("<Q", data, offset)[0]
    assert len(data) == 984, "unexpected release size"
    assert data[:2] == b"MZ" and u32(60) == 64
    pe, opt, section = 64, 88, 216
    assert data[pe:pe+4] == b"PE\0\0"
    assert u16(pe+4) == 0x8664 and u16(pe+6) == 1
    assert u16(pe+20) == 128 and u16(pe+22) == 0x23
    assert u16(opt) == 0x20b and u32(opt+108) == 2
    assert u32(opt+32) == u32(opt+36) == 4
    assert u32(opt+60) == u32(opt+16) == 256
    assert u32(opt+56) == len(data)
    assert u64(opt+24) == 0x140000000
    assert u16(opt+68) == 2 and u16(opt+70) == 0x100
    assert u64(opt+72) == 1048576 and u64(opt+80) == 131072
    assert data[section:section+8] == b".text\0\0\0"
    virtual_size, rva, raw_size, raw = struct.unpack_from("<IIII", data, section+8)
    assert rva == raw == 256, "low-alignment section must have RVA == file offset"
    assert virtual_size == raw_size == 728
    assert raw + raw_size == len(data), "all declared raw bytes must exist"
    assert rva % 4 == raw_size % 4 == 0
    assert u32(section+36) == 0x60000020
    imports, size = struct.unpack_from("<II", data, opt+120)
    assert rva <= imports and imports+40 <= len(data) and size == 40
    lookup, stamp, chain, dll, iat = struct.unpack_from("<IIIII", data, imports)
    assert lookup == stamp == chain == 0, "IAT must also serve as the lookup table"
    assert data[imports+20:imports+40] == bytes(20)
    assert iat % 8 == 0 and rva <= iat and iat+64 <= len(data)
    def cstring(offset):
        assert rva <= offset < len(data)
        return data[offset:data.index(0, offset)].decode("ascii")
    assert cstring(dll) == "KERNEL32.dll"
    names = []
    for index in range(7):
        entry = u64(iat+8*index)
        assert entry < 1 << 63, "named imports only"
        assert u16(entry) == 0
        names.append(cstring(entry+2))
    assert names == APIS and u64(iat+56) == 0
    print("PASS PE layout: 984 bytes, 4/4 alignment, one section, shared lookup/IAT", flush=True)

if __name__ == "__main__":
    check_pe(ROOT / "dist/daydir.exe")

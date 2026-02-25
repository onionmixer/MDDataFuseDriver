#!/usr/bin/env python3
"""
WS85: mdfsck 문자열 테이블 추출 - DRB/Extent 관련 printf 포맷 문자열
특정 데이터 오프셋의 문자열을 직접 추출
"""

import struct

with open("/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/w31/extract/mdfsck.exe", "rb") as f:
    data = f.read()

e_cparhdr = struct.unpack_from('<H', data, 8)[0]
code_offset = e_cparhdr * 16

# Format string addresses referenced in the code
# These are data segment offsets pushed before printf calls
# (push ds; push OFFSET; lcall printf)
string_offsets = [
    # From 0x1df2 function (DRB verbose output)
    (0x0d67, "dir name template"),
    (0x0d74, "entry header format"),
    (0x0d7c, "record field 1"),
    (0x0d87, "separator"),
    (0x0d8d, "byte +0x04 format"),
    (0x0d98, "EntryID format"),
    (0x0da0, "dir +0x28 format"),
    (0x0daa, "separator 2"),
    (0x0dba, "DataSize format (dir)"),
    (0x0dc6, "DRBLoc format"),
    (0x0dd1, "DRBNum format"),
    (0x0ddc, "file +0x38 format"),
    (0x0de7, "separator 3"),
    (0x0df7, "DataSize format (file)"),
    (0x0e03, "Extent1 Loc/StartAU format"),
    (0x0e0f, "Extent1 Num format"),
    (0x0e1b, "separator 4"),
    (0x0e2b, "Extent2 Loc format"),
    (0x0e37, "Extent2 Num format"),
    (0x0e43, "Extent3 Loc format"),
    (0x0e4f, "final separator"),
    # From 0x21ea function (extent verification)
    (0x0e8d, "read error format"),
    (0x0ea9, "unknown entry type"),
    (0x0ec6, "AEXTTYPE format"),
    (0x0ee9, "inline extent format"),
    (0x0f11, "DataSize mismatch"),
    (0x0f4f, "extent detail"),
    (0x0f66, "extent separator"),
    (0x0f68, "extent mismatch"),
    (0x0fa0, "allocated size"),
    (0x0fd6, "used extent"),
    (0x100b, "unknown 1"),
    (0x1033, "size compare"),
    (0x1077, "extent detail 2"),
    (0x108e, "extent label"),
    (0x1090, "extent mismatch 2"),
    (0x10ce, "allocated 2"),
    (0x110a, "used 2"),
    (0x1144, "final"),
    (0x1146, "verify mismatch"),
    (0x1164, "chain label"),
    (0x1173, "indentation"),
    (0x1177, "extent entry"),
    (0x11b3, "chain error"),
    (0x11de, "depth error"),
    (0x1217, "direct label"),
    (0x1226, "indentation 2"),
    (0x122a, "direct entry"),
    # From AEXT32 iteration (0x147e)
    (0x0b63, "extent count mismatch"),
    (0x0b92, "check header"),
    # From DRB validation (0x1560)
    (0x0ba1, "default dir name"),
    (0x0ba6, "MaxIdNum error"),
    (0x0bbf, "NumDir error"),
    (0x0be5, "NumFile error"),
    (0x0c05, "extent count"),
    (0x0c22, "NumAlloc error"),
    (0x0c43, "extent slot"),
    (0x0c7a, "dir name"),
    # From MTB code
    (0x093b, "MTB value error"),
    (0x0968, "MTB next"),
    (0x0974, "MTB range"),
    (0x09a0, "MTB discontinuity"),
    (0x09bc, "MTB verbose"),
    (0x0a6e, "MTB stat 1"),
    (0x0a81, "MTB stat 2"),
    (0x0a9c, "MTB stat 3"),
    (0x0ab3, "MTB stat 4"),
    (0x0acd, "MTB stat 5"),
    (0x0ae7, "MTB stat 6"),
    (0x0afe, "MTB size error"),
    # Extent format string
    (0x0f3c8 - code_offset, "Extent format") if 0x0f3c8 > code_offset else (0xf3c8, "?"),
]

def extract_string(data, offset):
    """Extract null-terminated string from data."""
    # The strings are in data segment, which in MZ EXE starts after code
    # Try both code-relative and file-relative offsets
    end = data.find(b'\x00', code_offset + offset, code_offset + offset + 200)
    if end > code_offset + offset:
        s = data[code_offset + offset:end]
        try:
            return s.decode('ascii')
        except:
            return s.hex()
    return f"(not found at {code_offset + offset:#x})"

print(f"Code offset in file: 0x{code_offset:04x}")
print(f"{'='*80}")
print(f"  mdfsck 포맷 문자열 테이블")
print(f"{'='*80}")

for ds_offset, label in string_offsets:
    s = extract_string(data, ds_offset)
    if s and len(s) > 0 and s != f"(not found at {code_offset + ds_offset:#x})":
        print(f"  DS:{ds_offset:04x}: [{label:30s}] \"{s}\"")

# Also find "Extent" string in file
print(f"\n{'='*80}")
print(f"  'Extent' 문자열 직접 탐색")
print(f"{'='*80}")
pos = 0
while True:
    pos = data.find(b'Extent', pos)
    if pos == -1:
        break
    end = data.find(b'\x00', pos, pos + 100)
    if end > pos:
        try:
            s = data[pos:end].decode('ascii')
            rel_offset = pos - code_offset
            print(f"  File+0x{pos:05x} (DS:{rel_offset:04x}): \"{s}\"")
        except:
            pass
    pos += 1

# Search for key DRB field format strings
print(f"\n{'='*80}")
print(f"  필드명 패턴 탐색")
print(f"{'='*80}")
for pattern in [b'Loc=', b'Num=', b'Size=', b'Attr', b'Type', b'Name',
                b'DirLen', b'NumChild', b'ExtAU', b'RecLen', b'RecType',
                b'Start', b'Chain', b'ExtRec', b'Fxtrec', b'AaExtrec',
                b'Unknown', b'=%d', b'=%ld', b'=%04x', b'=%08lx',
                b'Depth', b'depth', b'Level', b'level']:
    pos = 0
    while True:
        pos = data.find(pattern, pos)
        if pos == -1:
            break
        # Extract surrounding context
        start = max(0, pos - 20)
        end = data.find(b'\x00', pos, pos + 80)
        if end == -1:
            end = pos + 40
        # Find string start
        str_start = pos
        while str_start > start and data[str_start-1:str_start] != b'\x00':
            str_start -= 1
        try:
            s = data[str_start:end].decode('ascii')
            if s.isprintable() and len(s) > 2:
                rel = str_start - code_offset
                print(f"  DS:{rel:04x}: \"{s}\"")
        except:
            pass
        pos += len(pattern)

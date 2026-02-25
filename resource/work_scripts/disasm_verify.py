#!/usr/bin/env python3
"""
WS85: DRB 레코드 실제 데이터 검증 + 5번째 필드명 탐색
"""

import struct

# 1. Z920.EXE DRB 레코드 raw hex 확인
with open("/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/work/mddata_mgmt.bin", "rb") as f:
    mgmt = f.read()

# DRB is at LBA 1061, in mgmt.bin the offset depends on what LBA range was captured
# mgmt.bin starts at LBA 0, so DRB at sector 1061 = offset 1061*2048
drb_offset = 1061 * 2048
if drb_offset < len(mgmt):
    drb_data = mgmt[drb_offset:drb_offset + 2048]
    print(f"DRB sector at file offset 0x{drb_offset:x}")

    # Root entry (42 bytes)
    root = drb_data[:42]
    print(f"\n=== Root Entry (RecLen={root[1]}) ===")
    for i in range(0, len(root), 16):
        hex_str = ' '.join(f'{b:02x}' for b in root[i:i+16])
        print(f"  +{i:02x}: {hex_str}")

    # Z920.EXE entry (58 bytes)
    z920 = drb_data[42:42+58]
    print(f"\n=== Z920.EXE Entry (RecLen={z920[1]}) ===")
    for i in range(0, len(z920), 16):
        hex_str = ' '.join(f'{b:02x}' for b in z920[i:i+16])
        print(f"  +{i:02x}: {hex_str}")

    # Parse Z920.EXE extent fields
    print(f"\n=== Z920.EXE Extent 필드 파싱 ===")
    # All fields are BE (Big-Endian)
    floc = struct.unpack_from('>I', z920, 0x24)[0]
    fnum = struct.unpack_from('>I', z920, 0x28)[0]
    aloc = struct.unpack_from('>I', z920, 0x2C)[0]
    anum = struct.unpack_from('>I', z920, 0x30)[0]
    field34 = struct.unpack_from('>I', z920, 0x34)[0]
    byte38 = z920[0x38] if len(z920) > 0x38 else None
    byte39 = z920[0x39] if len(z920) > 0x39 else None

    print(f"  +0x24 FLoc  = {floc} (0x{floc:08x}) — StartAU")
    print(f"  +0x28 FNum  = {fnum} (0x{fnum:08x}) — AU count")
    print(f"  +0x2C ALoc  = {aloc} (0x{aloc:08x})")
    print(f"  +0x30 ANum  = {anum} (0x{anum:08x})")
    print(f"  +0x34 ???   = {field34} (0x{field34:08x})")
    print(f"  +0x38 byte  = {byte38:#04x}" if byte38 is not None else "  +0x38 N/A")
    print(f"  +0x39 byte  = {byte39:#04x}" if byte39 is not None else "  +0x39 N/A")

    # Cross-check
    print(f"\n  교차 검증:")
    print(f"  FLoc={floc} → LBA={floc*4} (expected 1568)")
    print(f"  FNum={fnum} → 파일크기 최대={fnum*8192} bytes (expected ≥ 1110476)")
    print(f"  ceil(1110476/8192) = {(1110476+8191)//8192}")

    # Parse Root extent fields
    print(f"\n=== Root Entry Extent 필드 파싱 ===")
    dloc = struct.unpack_from('>H', root, 0x24)[0]
    cnum = struct.unpack_from('>H', root, 0x26)[0]
    byte28_dir = root[0x28] if len(root) > 0x28 else None
    byte29_dir = root[0x29] if len(root) > 0x29 else None

    print(f"  +0x24 DLoc  = {dloc} (0x{dloc:04x}) — 하위 DRB 위치")
    print(f"  +0x26 CNum  = {cnum} (0x{cnum:04x}) — 하위 DRB 수")
    print(f"  +0x28 byte  = {byte28_dir:#04x}" if byte28_dir is not None else "  +0x28 N/A")
    print(f"  +0x29 byte  = {byte29_dir:#04x}" if byte29_dir is not None else "  +0x29 N/A")
else:
    print(f"DRB offset {drb_offset} exceeds mgmt.bin size {len(mgmt)}")
    # Try alternative: DRB might be relative to VMA start
    # VMALoc = 1056, DRBLoc = 5, so DRB at LBA 1061
    # If mgmt.bin only contains management sectors, DRB offset could be smaller
    print(f"mgmt.bin size: {len(mgmt)} bytes = {len(mgmt)//2048} sectors")

# 2. 5번째 필드명 탐색 - mdfsck 문자열 영역 집중 탐색
print(f"\n{'='*80}")
print(f"  mdfsck 문자열 영역 집중 탐색 (FLoc/FNum/ALoc/ANum 주변)")
print(f"{'='*80}")

with open("/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/w31/extract/mdfsck.exe", "rb") as f:
    exe = f.read()

# Find FLoc string in file
floc_pos = exe.find(b'FLoc=')
fnum_pos = exe.find(b'FNum=')
aloc_pos = exe.find(b'ALoc=')
anum_pos = exe.find(b'ANum=')

print(f"\n  FLoc at file+0x{floc_pos:05x}")
print(f"  FNum at file+0x{fnum_pos:05x}")
print(f"  ALoc at file+0x{aloc_pos:05x}")
print(f"  ANum at file+0x{anum_pos:05x}")

# Extract all strings from floc_pos-200 to anum_pos+200
print(f"\n  문자열 테이블 (FLoc 주변 ±200):")
start = max(0, floc_pos - 200)
end = min(len(exe), anum_pos + 200)
region = exe[start:end]

pos = 0
while pos < len(region):
    # Find start of string (after null)
    if pos == 0 or region[pos-1:pos] == b'\x00':
        # Find end of string
        null = region.find(b'\x00', pos)
        if null > pos:
            try:
                s = region[pos:null].decode('ascii')
                if s.isprintable() and len(s) > 2:
                    file_pos = start + pos
                    ds_pos = file_pos - 0x800  # code_offset
                    print(f"  File+0x{file_pos:05x} (DS:0x{ds_pos:04x}): \"{s}\"")
            except:
                pass
            pos = null + 1
            continue
    pos += 1

# 3. DLoc/CNum string search
print(f"\n  DLoc/CNum 문자열 탐색:")
dloc_pos = exe.find(b'DLoc=')
cnum_pos = exe.find(b'CNum=')
print(f"  DLoc at file+0x{dloc_pos:05x}" if dloc_pos != -1 else "  DLoc not found")
print(f"  CNum at file+0x{cnum_pos:05x}" if cnum_pos != -1 else "  CNum not found")

if dloc_pos != -1:
    start2 = max(0, dloc_pos - 100)
    end2 = min(len(exe), dloc_pos + 200)
    region2 = exe[start2:end2]
    print(f"\n  DLoc 주변 문자열:")
    pos = 0
    while pos < len(region2):
        if pos == 0 or region2[pos-1:pos] == b'\x00':
            null = region2.find(b'\x00', pos)
            if null > pos:
                try:
                    s = region2[pos:null].decode('ascii')
                    if s.isprintable() and len(s) > 2:
                        file_pos = start2 + pos
                        ds_pos = file_pos - 0x800
                        print(f"  File+0x{file_pos:05x} (DS:0x{ds_pos:04x}): \"{s}\"")
                except:
                    pass
                pos = null + 1
                continue
        pos += 1

# 4. +0x38 byte field meaning search
print(f"\n  +0x38 관련 문자열 (Rec, Type 주변):")
for pattern in [b'Rtype=', b'rtype=', b'RecType', b'rectype',
                b'Level=', b'level=', b'Depth=', b'depth=',
                b'Nlink=', b'nlink=', b'Mode=', b'mode=',
                b'Flag=', b'flag=', b'Count=', b'count=',
                b'Ext=', b'ext=', b'NumExt', b'numext']:
    pos = exe.find(pattern)
    while pos != -1:
        end_null = exe.find(b'\x00', pos, pos + 80)
        if end_null > pos:
            # Find start of string
            str_start = pos
            while str_start > 0 and exe[str_start-1:str_start] != b'\x00':
                str_start -= 1
            try:
                s = exe[str_start:end_null].decode('ascii')
                ds_pos = str_start - 0x800
                print(f"  DS:0x{ds_pos:04x}: \"{s}\"")
            except:
                pass
        pos = exe.find(pattern, pos + len(pattern))

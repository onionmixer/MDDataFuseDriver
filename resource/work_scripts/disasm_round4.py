#!/usr/bin/env python3
"""
WS85 Round 4: mdfsck 심층 역어셈블리
- 0x20ce: DRB 섹터 리더 함수 (DRB 반복에서 호출)
- 0x2190-0x2300: DRB 필드 접근 (+0x04, +0x05, +0x28, +0x2A)
- 0x2600-0x2700: AAEXTREC 처리 로직
- 0x147e-0x1550: AEXT32 듀얼 레코드 포맷 전체
- EntryType(+0x04) / Unknown05(+0x05) 접근 패턴 탐색
"""

import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_16

# Load mdfsck binary
with open("/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/w31/extract/mdfsck.exe", "rb") as f:
    data = f.read()

# MZ header → code offset
e_cblp = struct.unpack_from('<H', data, 2)[0]
e_cp = struct.unpack_from('<H', data, 4)[0]
e_cparhdr = struct.unpack_from('<H', data, 8)[0]
code_offset = e_cparhdr * 16
code_data = data[code_offset:]

cs = Cs(CS_ARCH_X86, CS_MODE_16)

def disasm_range(start, end, label=""):
    """Disassemble code range with label."""
    print(f"\n{'='*80}")
    print(f"  {label}")
    print(f"  Code offset 0x{start:04x} - 0x{end:04x}")
    print(f"{'='*80}")
    chunk = code_data[start:end]
    for insn in cs.disasm(chunk, start):
        print(f"  {insn.address:04x}: {insn.mnemonic:8s} {insn.op_str}")

# ===========================================================================
# 1. Function 0x20ce — DRB 섹터 리더 (DRB 반복 함수 0x1a48에서 call 0x20ce)
# ===========================================================================
disasm_range(0x20ce, 0x2190, "FUNC 0x20ce: DRB 섹터 리더 추정")

# ===========================================================================
# 2. DRB 필드 접근 영역 0x2190-0x2300
# ===========================================================================
disasm_range(0x2190, 0x2300, "DRB 필드 접근 (record+0x28, +0x2A, +0x04, +0x05)")

# ===========================================================================
# 3. DRB 필드 접근 확장 0x2300-0x2500
# ===========================================================================
disasm_range(0x2300, 0x2500, "DRB 필드 접근 확장")

# ===========================================================================
# 4. AAEXTREC/AFXTREC 처리 0x2500-0x2700
# ===========================================================================
disasm_range(0x2500, 0x2700, "AAEXTREC/AFXTREC 처리")

# ===========================================================================
# 5. AEXT32 듀얼 레코드 포맷 전체 0x1470-0x1560
# ===========================================================================
disasm_range(0x1470, 0x1560, "AEXT32 듀얼 레코드 포맷 (전체 범위)")

# ===========================================================================
# 6. DRB 반복 함수 0x1a48 확장 범위 (0x1a48-0x1c00)
# ===========================================================================
disasm_range(0x1a48, 0x1c00, "DRB 반복 함수 (확장)")

# ===========================================================================
# 7. EntryType(+0x04) 접근 패턴 탐색
#    byte [bx+4] 또는 byte [si+4] 또는 byte [di+4] 접근 탐색
# ===========================================================================
print(f"\n{'='*80}")
print(f"  EntryType(+0x04) / Unknown05(+0x05) 접근 패턴 탐색")
print(f"{'='*80}")

# Search for byte access patterns at +0x04 and +0x05 offsets
# in DRB-related code regions
search_ranges = [
    (0x1400, 0x1c00, "DRB 관련 루프"),
    (0x2000, 0x2800, "DRB 출력/검증"),
    (0x4f00, 0x5200, "플래그 처리"),
]

for start, end, label in search_ranges:
    chunk = code_data[start:end]
    found = []
    for insn in cs.disasm(chunk, start):
        op = insn.op_str.lower()
        # Look for access patterns to record+0x04 or +0x05
        if any(f'+ 4]' in op or f'+ 5]' in op or
               f'+4]' in op or f'+5]' in op
               for _ in [None]):
            found.append(f"  {insn.address:04x}: {insn.mnemonic:8s} {insn.op_str}")
    if found:
        print(f"\n  [{label}] +0x04/+0x05 접근:")
        for line in found:
            print(line)

# ===========================================================================
# 8. DRB +0x24/+0x26 접근 패턴 (이중 해석 확인)
# ===========================================================================
print(f"\n{'='*80}")
print(f"  DRB +0x24/+0x26 접근 패턴 탐색")
print(f"{'='*80}")

for start, end, label in search_ranges:
    chunk = code_data[start:end]
    found = []
    for insn in cs.disasm(chunk, start):
        op = insn.op_str.lower()
        if any(f'+ 0x24]' in op or f'+ 0x26]' in op or
               f'+0x24]' in op or f'+0x26]' in op
               for _ in [None]):
            found.append(f"  {insn.address:04x}: {insn.mnemonic:8s} {insn.op_str}")
    if found:
        print(f"\n  [{label}] +0x24/+0x26 접근:")
        for line in found:
            print(line)

# ===========================================================================
# 9. DRB +0x02 (Attributes) 접근 패턴
# ===========================================================================
print(f"\n{'='*80}")
print(f"  DRB Attributes(+0x02) 접근 패턴 탐색")
print(f"{'='*80}")

for start, end, label in search_ranges:
    chunk = code_data[start:end]
    found = []
    for insn in cs.disasm(chunk, start):
        op = insn.op_str.lower()
        if any(f'+ 2]' in op or f'+2]' in op
               for _ in [None]):
            # filter to only word-size or explicit references
            found.append(f"  {insn.address:04x}: {insn.mnemonic:8s} {insn.op_str}")
    if found:
        print(f"\n  [{label}] +0x02 접근 (상위 10개):")
        for line in found[:10]:
            print(line)
        if len(found) > 10:
            print(f"  ... ({len(found)} total)")

# ===========================================================================
# 10. RecLen(+0x01) 접근 패턴과 레코드 순회 로직
# ===========================================================================
print(f"\n{'='*80}")
print(f"  RecLen(+0x01) 접근 패턴")
print(f"{'='*80}")

for start, end, label in search_ranges:
    chunk = code_data[start:end]
    found = []
    for insn in cs.disasm(chunk, start):
        op = insn.op_str.lower()
        if any(f'+ 1]' in op or f'+1]' in op for _ in [None]):
            if 'byte' in op or insn.mnemonic in ('mov', 'cmp', 'add', 'sub'):
                found.append(f"  {insn.address:04x}: {insn.mnemonic:8s} {insn.op_str}")
    if found:
        print(f"\n  [{label}] +0x01 접근:")
        for line in found[:15]:
            print(line)
        if len(found) > 15:
            print(f"  ... ({len(found)} total)")

# ===========================================================================
# 11. DRB 관련 printf/emit 문자열 탐색
# ===========================================================================
print(f"\n{'='*80}")
print(f"  DRB 관련 문자열 참조 탐색")
print(f"{'='*80}")

# Search for strings related to DRB fields in the data section
interesting_strings = []
for i in range(len(data)):
    # Look for ASCII strings > 5 chars
    if data[i:i+3] in (b'Dir', b'dir', b'Rec', b'rec', b'Ent', b'ent',
                         b'Ext', b'ext', b'Typ', b'typ', b'Att', b'att',
                         b'Fix', b'fix', b'Siz', b'siz', b'nam', b'Nam',
                         b'DRB', b'drb', b'ERB', b'erb', b'MTB', b'mtb',
                         b'VSB', b'vsb'):
        # Extract null-terminated string
        end = data.find(b'\x00', i, i+80)
        if end > i + 3:
            s = data[i:end]
            try:
                txt = s.decode('ascii')
                if txt.isprintable() and len(txt) > 4:
                    interesting_strings.append((i, txt))
            except:
                pass

# Deduplicate and print
seen = set()
for offset, txt in interesting_strings:
    if txt not in seen:
        seen.add(txt)
        print(f"  File+0x{offset:04x}: \"{txt}\"")

# ===========================================================================
# 12. DRB 검증 함수 0x1560 주변 확장 (서브디렉토리/파일 분기 확인)
# ===========================================================================
disasm_range(0x1560, 0x1700, "DRB 검증 함수 확장 (서브디렉토리/파일 분기)")

# ===========================================================================
# 13. MTB TRAILER 관련 코드 탐색
#     MTB TRAILER value=2, tag=0x00 → 0x00 태그 접근 패턴
# ===========================================================================
print(f"\n{'='*80}")
print(f"  MTB 관련 코드 영역 탐색")
print(f"{'='*80}")

# MTBLoc is at 0x5b78, MTBNum at 0x5b7a
# Search for references to these addresses
mtb_refs = []
for insn in cs.disasm(code_data, 0):
    op = insn.op_str.lower()
    if '0x5b78' in op or '0x5b7a' in op:
        mtb_refs.append(f"  {insn.address:04x}: {insn.mnemonic:8s} {insn.op_str}")
print(f"\n  MTBLoc(0x5b78) / MTBNum(0x5b7a) 참조:")
for line in mtb_refs:
    print(line)

# Find MTB parsing code (around the references)
if mtb_refs:
    # Get addresses of MTB references
    mtb_addrs = []
    for ref in mtb_refs:
        addr = int(ref.strip().split(':')[0], 16)
        mtb_addrs.append(addr)

    # Find unique code regions (group within 0x100 range)
    regions = set()
    for addr in mtb_addrs:
        regions.add(addr & ~0xFF)

    for region_base in sorted(regions):
        # Only disasm MTB-specific regions not already covered
        if region_base not in (0x0400, 0x0500, 0x0700, 0x0f00):
            disasm_range(region_base, min(region_base + 0x100, len(code_data)),
                        f"MTB 코드 영역 0x{region_base:04x}")

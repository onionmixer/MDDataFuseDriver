#!/usr/bin/env python3
"""
WS85 Round 5: DRB 레코드 파싱 함수 심층 분석
- 0x1672: DRB 레코드 필드 byte-swap + 파싱 함수
- 0x1df2: 서브디렉토리 처리 함수
- 0x2620-0x2c6e: Extent 체인 분석 함수
- 0x21ea-0x22a0: DRB verbose 출력 (필드별 printf)
- 0x2734 컨텍스트: +0x04 접근
- 0x27xx: 속성 출력 코드
"""

import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_16

with open("/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/w31/extract/mdfsck.exe", "rb") as f:
    data = f.read()

e_cparhdr = struct.unpack_from('<H', data, 8)[0]
code_offset = e_cparhdr * 16
code_data = data[code_offset:]

cs = Cs(CS_ARCH_X86, CS_MODE_16)

def disasm_range(start, end, label=""):
    print(f"\n{'='*80}")
    print(f"  {label}")
    print(f"  Code offset 0x{start:04x} - 0x{end:04x}")
    print(f"{'='*80}")
    chunk = code_data[start:end]
    for insn in cs.disasm(chunk, start):
        print(f"  {insn.address:04x}: {insn.mnemonic:8s} {insn.op_str}")

# ===========================================================================
# 1. DRB 레코드 파싱/byte-swap 함수 0x1672 (전체)
#    - 레코드 필드별 byte-swap (BE→LE)
#    - EntryType, Unknown05, 속성 등 필드 접근 패턴 확인
# ===========================================================================
disasm_range(0x1672, 0x1a48, "FUNC 0x1672: DRB 레코드 파싱/byte-swap")

# ===========================================================================
# 2. 서브디렉토리 처리 함수 0x1df2
# ===========================================================================
disasm_range(0x1df2, 0x2000, "FUNC 0x1df2: 서브디렉토리 처리")

# ===========================================================================
# 3. DRB verbose 출력 0x21ea-0x22c0 (필드별 printf)
#    - 0x2734 컨텍스트 포함
# ===========================================================================
disasm_range(0x21ea, 0x2300, "DRB verbose 출력 (필드별)")

# ===========================================================================
# 4. Extent 체인 분석 함수 0x2620 (전체)
# ===========================================================================
disasm_range(0x2620, 0x2c6e, "FUNC 0x2620: Extent 체인 분석")

# ===========================================================================
# 5. 함수 0x2c6e (extent 유틸리티)
# ===========================================================================
disasm_range(0x2c6e, 0x2e00, "FUNC 0x2c6e: Extent 유틸리티")

# ===========================================================================
# 6. 문자열 테이블 - DRB 관련 printf 포맷 문자열 추출
# ===========================================================================
print(f"\n{'='*80}")
print(f"  DRB/Extent 관련 printf 포맷 문자열")
print(f"{'='*80}")

# Search data area for format strings
i = 0
while i < len(data):
    if data[i] == 0x25 and i > 0 and data[i-1:i].isalpha():  # check for %
        pass
    # Find strings containing field-related keywords
    if i + 3 < len(data):
        try:
            # Find null-terminated strings
            null_pos = data.find(b'\x00', i, i + 120)
            if null_pos > i + 2:
                s = data[i:null_pos]
                txt = s.decode('ascii', errors='ignore')
                if txt.isprintable() and len(txt) > 3:
                    # Filter for relevant strings
                    lower = txt.lower()
                    if any(kw in lower for kw in [
                        '%', 'loc', 'num', 'ext', 'rec', 'dir', 'file',
                        'attr', 'size', 'name', 'data', 'err', 'def',
                        'free', 'used', 'avail', 'typ', 'id', 'child',
                        'alloc', 'space', 'trail', 'next', 'mtb', 'vsb',
                        'drb', 'erb', 'vma', 'entry', 'extent']):
                        print(f"  File+0x{i:05x}: \"{txt}\"")
                        i = null_pos + 1
                        continue
        except:
            pass
    i += 1

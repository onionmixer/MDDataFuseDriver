#!/usr/bin/env python3
"""
VSB 비트맵 2-bit/AU 인코딩 최종 검증

발견:
- VSB 3섹터 = 6144 bytes = 24576 AU 슬롯 (2-bit/AU, 4 AU/byte)
- NumAlloc = 17616 → 유효 슬롯 = 17616, 패딩 = 24576 - 17616 = 6960
- VSB[2] bytes 308-2047 = 0xFF → 패딩 (NumAlloc 초과 영역)
"""
import struct

IMG = "/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/work/mddata_mgmt.bin"
SECTOR = 2048
AU_SIZE = 4

with open(IMG, "rb") as f:
    img = f.read()

# VD 값
vd_off = 1056 * SECTOR
num_alloc = struct.unpack_from(">I", img, vd_off + 0x18)[0]
num_used = struct.unpack_from(">I", img, vd_off + 0x24)[0]
num_available = struct.unpack_from(">I", img, vd_off + 0x20)[0]
num_defective = struct.unpack_from(">I", img, vd_off + 0x28)[0]
reserved = num_alloc - num_used - num_available

# VSB 3섹터 연결
vsb = b""
for i in range(3):
    off = (1057 + i) * SECTOR
    vsb += img[off:off + SECTOR]

# 2-bit/AU 디코딩 (MSB-first: byte 내에서 bit7-6=AU[0], bit5-4=AU[1], ...)
def get_au_state(au_num):
    byte_idx = au_num // 4
    pair_idx = 3 - (au_num % 4)  # MSB-first
    return (vsb[byte_idx] >> (pair_idx * 2)) & 0x03

STATE_NAMES = {0: "FREE", 1: "USED", 2: "DEFECTIVE", 3: "RESERVED"}

# === 유효 AU만 카운트 (NumAlloc 범위 내) ===
print("=== 2-bit/AU 인코딩 최종 검증 ===")
print(f"VSB 총 슬롯: {len(vsb) * 4} (= {len(vsb)} bytes × 4 AU/byte)")
print(f"유효 AU: {num_alloc} (NumAlloc)")
print(f"패딩 슬롯: {len(vsb) * 4 - num_alloc}")
print()

counts = {0: 0, 1: 0, 2: 0, 3: 0}
for au in range(num_alloc):
    state = get_au_state(au)
    counts[state] += 1

print("유효 AU 내 상태 분포:")
print(f"  00 (FREE):      {counts[0]:6d}  vs NumAvailable = {num_available:6d}  {'✓' if counts[0] == num_available else '✗'}")
print(f"  01 (USED):      {counts[1]:6d}  vs NumUsed      = {num_used:6d}  {'✓' if counts[1] == num_used else '✗'}")
print(f"  10 (DEFECTIVE): {counts[2]:6d}  vs NumDefective = {num_defective:6d}  {'✓' if counts[2] == num_defective else '✗'}")
print(f"  11 (RESERVED):  {counts[3]:6d}  vs Reserved     = {reserved:6d}  {'✓' if counts[3] == reserved else '✗'}")
print(f"  합계:           {sum(counts.values()):6d}  vs NumAlloc     = {num_alloc:6d}  {'✓' if sum(counts.values()) == num_alloc else '✗'}")
print()

all_match = (counts[0] == num_available and counts[1] == num_used
             and counts[2] == num_defective and counts[3] == reserved)
print(f"전체 일치: {'✓ CONFIRMED' if all_match else '✗ MISMATCH'}")
print()

# === 패딩 영역 검증 ===
print("=== 패딩 영역 검증 ===")
padding_vals = {0: 0, 1: 0, 2: 0, 3: 0}
total_padding = len(vsb) * 4 - num_alloc
for au in range(num_alloc, len(vsb) * 4):
    state = get_au_state(au)
    padding_vals[state] += 1

print(f"패딩 슬롯 ({total_padding}개):")
for v in sorted(padding_vals):
    if padding_vals[v] > 0:
        print(f"  {v:02b}: {padding_vals[v]}")
all_padding_ff = (padding_vals[3] == total_padding)
print(f"전부 11 (0xFF 패딩): {'✓' if all_padding_ff else '✗'}")
print()

# === AU 영역별 상태 맵 ===
print("=== AU 영역별 상태 맵 ===")

regions = [
    (0, 255, "Lead-in (LBA 0-1023)"),
    (256, 263, "Pre-VMA (LBA 1024-1055, zeros)"),
    (264, 265, "VD/VSB/MTB/DRB (LBA 1056-1063)"),
    (266, 391, "VMA 예약 공간 (LBA 1064-1567, zeros)"),
    (392, 527, "Z920.EXE (LBA 1568-2111)"),
    (528, 946, "잔해 데이터 영역 (LBA 2112-3787)"),
    (947, 8191, "미기록 영역 (VSB[0] 나머지)"),
    (8192, 16383, "미기록 영역 (VSB[1])"),
    (16384, 17615, "미기록 영역 (VSB[2] 유효)"),
]

for au_start, au_end, label in regions:
    if au_start >= num_alloc:
        break
    au_end = min(au_end, num_alloc - 1)
    rc = {0: 0, 1: 0, 2: 0, 3: 0}
    for au in range(au_start, au_end + 1):
        rc[get_au_state(au)] += 1
    total = au_end - au_start + 1
    parts = []
    for v in [3, 1, 0, 2]:
        if rc[v] > 0:
            parts.append(f"{STATE_NAMES[v]}={rc[v]}")
    print(f"  AU {au_start:5d}–{au_end:5d} ({total:5d} AU): {', '.join(parts):30s}  {label}")

print()

# === 인코딩 사양 요약 ===
print("=== VSB 비트맵 인코딩 사양 ===")
print()
print("포맷: 2-bit per AU, MSB-first within byte")
print("  1 byte = 4 AU: [AU₀ AU₁ AU₂ AU₃]")
print("  AU₀ = bits 7-6, AU₁ = bits 5-4, AU₂ = bits 3-2, AU₃ = bits 1-0")
print()
print("상태 코드:")
print("  00 = FREE      (할당 가능)")
print("  01 = USED      (파일/관리 데이터에 할당됨)")
print("  10 = DEFECTIVE (결함 AU)")
print("  11 = RESERVED  (시스템 예약, lead-in 등)")
print()
print("레이아웃:")
print(f"  VSB[0] (LBA 1057): AU 0–8191     ({SECTOR} bytes)")
print(f"  VSB[1] (LBA 1058): AU 8192–16383  ({SECTOR} bytes)")
print(f"  VSB[2] (LBA 1059): AU 16384–17615 (유효) + 17616–24575 (0xFF 패딩)")
print(f"  섹터당 용량: {SECTOR} bytes × 4 AU/byte = {SECTOR * 4} AU")
print(f"  VSBNum 계산: ceil({num_alloc} / {SECTOR * 4}) = {(num_alloc + SECTOR * 4 - 1) // (SECTOR * 4)}")
print()

# === 0x55 패턴 역해석 ===
print("=== 0x55 패턴 역해석 ===")
print(f"0x55 = 01010101₂ → [01][01][01][01] → 4 AU 모두 USED")
print(f"0xFF = 11111111₂ → [11][11][11][11] → 4 AU 모두 RESERVED")
print(f"0x00 = 00000000₂ → [00][00][00][00] → 4 AU 모두 FREE")
print()
print(f"VSB[0] 할당맵: [RESERVED×256] [USED×272] [FREE×7664]")
print(f"  RESERVED AU 0-255: lead-in 영역")
print(f"  USED AU 256-527: VMA 구조 + Z920.EXE")
print(f"    - AU 256-391 (136 AU): VMA/관리 영역")
print(f"    - AU 392-527 (136 AU): Z920.EXE 파일 데이터")
print(f"  FREE AU 528-8191: 미할당")

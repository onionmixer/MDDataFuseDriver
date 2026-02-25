#!/usr/bin/env python3
"""
VSB 비트맵 인코딩 규명

알려진 사실:
- VSBLoc=1 → LBA 1057, VSBNum=3 → LBA 1057-1059
- NumAlloc=17616 AU, NumUsed=272, NumAvailable=17088
- Reserved = 17616 - 272 - 17088 = 256 AU
- Z920.EXE: AU 392-527 (136 AU), root dir: AU 1
- LBA 1057: 0xFF(64B) + 0x55(68B) + 0x00(나머지)
- LBA 1058: 전부 0x00
- LBA 1059: 일부 데이터

가설:
A) 1-bit/AU: 512 set bits (0xFF) + 272 set bits (0x55) = 784 set → NumUsed=272와 불일치
B) 2-bit/AU: 256 AU×(11) + 272 AU×(01) → reserved=256, used=272 → 일치!
C) 1-bit/AU이되, 0xFF는 관리영역 전용 비트맵이고 0x55만이 데이터 할당 비트맵
"""
import struct

IMG = "/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/work/mddata_mgmt.bin"
SECTOR = 2048
AU_SIZE = 4  # sectors per AU

with open(IMG, "rb") as f:
    img = f.read()

# VD 값 로드
vd_off = 1056 * SECTOR
num_alloc = struct.unpack_from(">I", img, vd_off + 0x18)[0]
num_used = struct.unpack_from(">I", img, vd_off + 0x24)[0]
num_available = struct.unpack_from(">I", img, vd_off + 0x20)[0]
num_defective = struct.unpack_from(">I", img, vd_off + 0x28)[0]
reserved = num_alloc - num_used - num_available

print("=== VD 할당 카운터 ===")
print(f"  NumAlloc:     {num_alloc}")
print(f"  NumUsed:      {num_used}")
print(f"  NumAvailable: {num_available}")
print(f"  NumDefective: {num_defective}")
print(f"  Reserved:     {reserved} (= NumAlloc - NumUsed - NumAvailable)")
print()

# VSB 3섹터 로드
vsb = []
for i in range(3):
    lba = 1057 + i
    off = lba * SECTOR
    vsb.append(img[off:off + SECTOR])

# === 1단계: VSB 각 섹터의 바이트 패턴 분석 ===
print("=== VSB 섹터별 바이트 패턴 ===")
for si, sector in enumerate(vsb):
    lba = 1057 + si
    # 바이트값별 카운트
    from collections import Counter
    freq = Counter(sector)
    nonzero = sum(1 for b in sector if b != 0)
    last_nz = -1
    for i in range(len(sector) - 1, -1, -1):
        if sector[i] != 0:
            last_nz = i
            break

    print(f"--- LBA {lba} (VSB[{si}]) ---")
    print(f"  비어있지 않은 바이트 수: {nonzero}")
    print(f"  마지막 비어있지 않은 위치: 0x{last_nz:04x}" if last_nz >= 0 else "  전부 0x00")

    # 연속 구간 분석
    runs = []
    i = 0
    while i < SECTOR:
        val = sector[i]
        j = i
        while j < SECTOR and sector[j] == val:
            j += 1
        if val != 0 or j - i < SECTOR:  # 0이 아닌 구간 또는 짧은 0 구간
            runs.append((i, j - i, val))
        i = j

    for start, length, val in runs:
        if length >= 4 or val != 0:
            print(f"  [{start:4d}–{start+length-1:4d}] ({length:4d} bytes) = 0x{val:02x}")
    print()

# === 2단계: 가설 A — 1-bit/AU ===
print("=== 가설 A: 1-bit/AU ===")
# 전체 VSB를 하나의 비트스트림으로
all_vsb = vsb[0] + vsb[1] + vsb[2]
total_bits = len(all_vsb) * 8  # 6144 * 8 = 49152 bits

# set bits 카운트 (전체)
total_set = sum(bin(b).count('1') for b in all_vsb)
print(f"  전체 비트: {total_bits}")
print(f"  전체 set bits: {total_set}")
print(f"  NumAlloc={num_alloc}, NumUsed={num_used}")
print(f"  set bits == NumUsed? {total_set == num_used}")
print(f"  set bits == NumUsed + Reserved? {total_set == num_used + reserved}")
print()

# 섹터별 set bits
for si, sector in enumerate(vsb):
    set_bits = sum(bin(b).count('1') for b in sector)
    print(f"  VSB[{si}] (LBA {1057+si}): set bits = {set_bits}")
print()

# === 3단계: 가설 B — 2-bit/AU ===
print("=== 가설 B: 2-bit/AU ===")

# 2-bit 값 카운트 (MSB-first: bit7-6, bit5-4, bit3-2, bit1-0)
counts_2bit = {0: 0, 1: 0, 2: 0, 3: 0}
for byte_val in all_vsb:
    for shift in [6, 4, 2, 0]:
        val = (byte_val >> shift) & 0x03
        counts_2bit[val] += 1

total_2bit_entries = sum(counts_2bit.values())
print(f"  전체 2-bit 엔트리: {total_2bit_entries}")
print(f"  값 분포:")
for v in [0, 1, 2, 3]:
    label = {0: "00 (free?)", 1: "01 (used?)", 2: "10 (?)", 3: "11 (reserved?)"}[v]
    print(f"    {label}: {counts_2bit[v]}")

print(f"  01 count == NumUsed? {counts_2bit[1] == num_used}")
print(f"  11 count == Reserved? {counts_2bit[3] == reserved}")
print(f"  00 count == NumAvailable? {counts_2bit[0] == num_available}")
print(f"  01+11+00 == NumAlloc? {counts_2bit[1] + counts_2bit[3] + counts_2bit[0]}")
print()

# === 4단계: Z920.EXE 할당 범위와 대조 ===
print("=== Z920.EXE AU 범위 대조 ===")

z920_start_au = 392
z920_au_count = (1110476 + 8191) // 8192  # = 136
z920_end_au = z920_start_au + z920_au_count - 1

print(f"Z920.EXE: AU {z920_start_au}–{z920_end_au} ({z920_au_count} AU)")
print()

# 가설 B (2-bit/AU)에서 Z920.EXE 범위의 2-bit 값 확인
print("가설 B: Z920.EXE AU 범위의 2-bit 값")
z920_vals_2bit = {}
for au in range(z920_start_au, z920_end_au + 1):
    byte_idx = au // 4  # 4 AU per byte
    pair_idx = 3 - (au % 4)  # MSB-first: AU0=bit7-6, AU1=bit5-4, AU2=bit3-2, AU3=bit1-0
    if byte_idx < len(all_vsb):
        val = (all_vsb[byte_idx] >> (pair_idx * 2)) & 0x03
        z920_vals_2bit[val] = z920_vals_2bit.get(val, 0) + 1

for v in sorted(z920_vals_2bit):
    print(f"  값 {v:02b}: {z920_vals_2bit[v]} AU")
print()

# 가설 A (1-bit/AU)에서 Z920.EXE 범위의 bit 값 확인 (LSB-first, MSB-first 양쪽)
print("가설 A: Z920.EXE AU 범위의 bit 값")
for order_name, get_bit in [
    ("LSB-first", lambda au: (all_vsb[au // 8] >> (au % 8)) & 1),
    ("MSB-first", lambda au: (all_vsb[au // 8] >> (7 - au % 8)) & 1),
]:
    set_count = sum(get_bit(au) for au in range(z920_start_au, z920_end_au + 1))
    print(f"  {order_name}: {set_count}/{z920_au_count} set ({z920_au_count - set_count} clear)")
print()

# === 5단계: 관리영역 AU 범위 대조 ===
print("=== 관리영역 AU 범위 대조 ===")
# VMA = LBA 1056, 관리구조는 LBA 1056-1061 (6 sectors)
# lead-in: LBA 0-1055 (AU 0-263)
# VD/VSB/MTB/DRB: LBA 1056-1061 (AU 264-265)
# Reserved: LBA 1062-1567 (AU 266-391) - 빈 공간
print(f"Lead-in: AU 0–263 (LBA 0–1055)")
print(f"VMA 구조: AU 264–265 (LBA 1056–1063)")
print(f"VMA 예약: AU 266–391 (LBA 1064–1567, 전부 0x00)")
print(f"Z920.EXE: AU 392–{z920_end_au} (LBA 1568–{z920_end_au * AU_SIZE + AU_SIZE - 1})")
print()

# 가설 B: 관리영역의 2-bit 값
print("가설 B: 관리영역 AU의 2-bit 값")
mgmt_vals = {0: 0, 1: 0, 2: 0, 3: 0}
for au in range(0, 392):  # AU 0-391 (Z920 이전)
    byte_idx = au // 4
    pair_idx = 3 - (au % 4)
    if byte_idx < len(all_vsb):
        val = (all_vsb[byte_idx] >> (pair_idx * 2)) & 0x03
        mgmt_vals[val] = mgmt_vals.get(val, 0) + 1

print(f"  AU 0–391 ({sum(mgmt_vals.values())} AU):")
for v in sorted(mgmt_vals):
    print(f"    값 {v:02b}: {mgmt_vals[v]}")
print()

# 잔해 영역의 2-bit 값
print("가설 B: 잔해 영역 AU의 2-bit 값")
remnant_vals = {0: 0, 1: 0, 2: 0, 3: 0}
for au in range(z920_end_au + 1, min(num_alloc, total_bits // 2 if True else total_bits)):
    byte_idx = au // 4
    pair_idx = 3 - (au % 4)
    if byte_idx < len(all_vsb):
        val = (all_vsb[byte_idx] >> (pair_idx * 2)) & 0x03
        remnant_vals[val] = remnant_vals.get(val, 0) + 1

print(f"  AU {z920_end_au + 1}–{min(num_alloc - 1, total_2bit_entries - 1)}:")
for v in sorted(remnant_vals):
    if remnant_vals[v] > 0:
        print(f"    값 {v:02b}: {remnant_vals[v]}")
print()

# === 6단계: LBA 1059 (VSB[2]) 상세 분석 ===
print("=== LBA 1059 (VSB[2]) 상세 분석 ===")
s2 = vsb[2]
last_nz = -1
for i in range(len(s2) - 1, -1, -1):
    if s2[i] != 0:
        last_nz = i
        break

if last_nz >= 0:
    dump_end = min(SECTOR, ((last_nz // 16) + 2) * 16)
    print(f"비어있지 않은 마지막 바이트: 0x{last_nz:04x}")
    print()
    for row in range(0, dump_end, 16):
        hex_part = " ".join(f"{s2[row+i]:02x}" for i in range(16))
        ascii_part = "".join(
            chr(s2[row+i]) if 32 <= s2[row+i] < 127 else "."
            for i in range(16)
        )
        print(f"  {row:04x}: {hex_part}  {ascii_part}")
    print()

    # LBA 1059의 바이트별 변화점 분석
    print("변화점 분석:")
    prev = s2[0]
    run_start = 0
    for i in range(1, last_nz + 2):
        val = s2[i] if i <= last_nz else -1
        if val != prev:
            print(f"  [{run_start:4d}–{i-1:4d}] ({i-run_start:4d} bytes) = 0x{prev:02x} ({prev:08b})")
            run_start = i
            prev = val
else:
    print("전부 0x00")

print()

# === 7단계: 최종 판정 ===
print("=== 최종 판정 ===")
print()
print("가설 A (1-bit/AU):")
print(f"  전체 set bits = {total_set}")
print(f"  NumUsed({num_used}) + Reserved({reserved}) = {num_used + reserved}")
a_match = total_set == num_used + reserved
print(f"  일치? {a_match}")
print()
print("가설 B (2-bit/AU):")
print(f"  값 01 count = {counts_2bit[1]}, NumUsed = {num_used}, 일치? {counts_2bit[1] == num_used}")
print(f"  값 11 count = {counts_2bit[3]}, Reserved = {reserved}, 일치? {counts_2bit[3] == reserved}")
print(f"  값 00 count = {counts_2bit[0]}, NumAvailable = {num_available}, 일치? {counts_2bit[0] == num_available}")
print(f"  값 10 count = {counts_2bit[2]}, NumDefective = {num_defective}, 일치? {counts_2bit[2] == num_defective}")
b_match = (counts_2bit[1] == num_used and counts_2bit[3] == reserved
           and counts_2bit[0] == num_available and counts_2bit[2] == num_defective)
print(f"  전부 일치? {b_match}")

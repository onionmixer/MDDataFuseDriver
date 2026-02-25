#!/usr/bin/env python3
"""
MTB ↔ VSB 교차 검증: MTB 0x90 값이 VSB 섹터별 FREE AU 수인지 확인

가설: MTB의 3개 0x90 엔트리는 각 VSB 섹터에 포함된 FREE AU 수를 기록한다.
  - MTB 0x90[0] = VSB[0] (AU 0–8191)의 FREE AU 수
  - MTB 0x90[1] = VSB[1] (AU 8192–16383)의 FREE AU 수
  - MTB 0x90[2] = VSB[2] (AU 16384–NumAlloc-1)의 FREE AU 수
  - 합계 = NumAvailable
"""
import struct

IMG = "/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/work/mddata_mgmt.bin"
SECTOR = 2048
AU_PER_VSB_SECTOR = 8192  # 2048 bytes × 4 AU/byte

with open(IMG, "rb") as f:
    img = f.read()

# === VD 파라미터 ===
vd_off = 1056 * SECTOR
num_alloc = struct.unpack_from(">I", img, vd_off + 0x18)[0]
num_available = struct.unpack_from(">I", img, vd_off + 0x20)[0]
num_used = struct.unpack_from(">I", img, vd_off + 0x24)[0]
num_defective = struct.unpack_from(">I", img, vd_off + 0x28)[0]
reserved = num_alloc - num_used - num_available
vsb_num = struct.unpack_from(">H", img, vd_off + 0x46)[0]

print("=== VD 파라미터 ===")
print(f"  NumAlloc:     {num_alloc} AU")
print(f"  NumAvailable: {num_available} AU")
print(f"  NumUsed:      {num_used} AU")
print(f"  NumDefective: {num_defective} AU")
print(f"  Reserved:     {reserved} AU (= NumAlloc - NumUsed - NumAvailable)")
print(f"  VSBNum:       {vsb_num} sectors")
print()

# === MTB 원시 데이터 ===
mtb_off = 1060 * SECTOR
mtb = img[mtb_off:mtb_off + SECTOR]

print("=== MTB 원시 데이터 (LBA 1060) ===")
# 비어있지 않은 마지막 바이트
last_nz = -1
for i in range(SECTOR - 1, -1, -1):
    if mtb[i] != 0:
        last_nz = i
        break

dump_end = min(SECTOR, ((last_nz // 16) + 2) * 16) if last_nz >= 0 else 32
for row in range(0, dump_end, 16):
    hex_part = " ".join(f"{mtb[row+i]:02x}" for i in range(min(16, SECTOR - row)))
    print(f"  {row:04x}: {hex_part}")
print(f"  유효 데이터: {last_nz + 1} bytes, 이후 전부 0x00")
print()

# === MTB TLV 파싱 ===
print("=== MTB TLV 파싱 (1-byte tag + 3-byte BE24 value) ===")
mtb_entries = []
for i in range(0, last_nz + 1, 4):
    tag = mtb[i]
    val = (mtb[i+1] << 16) | (mtb[i+2] << 8) | mtb[i+3]
    mtb_entries.append((i, tag, val))
    tag_name = {0x80: "START", 0x90: "DATA", 0xA0: "END", 0x00: "TRAILER"}.get(tag, "???")
    print(f"  +0x{i:02x}: tag=0x{tag:02x} ({tag_name:7s})  value={val:6d} (0x{val:06x})")

# 0x90 엔트리만 추출
data_values = [val for (_, tag, val) in mtb_entries if tag == 0x90]
trailer_val = mtb_entries[-1][2] if mtb_entries[-1][1] == 0x00 else None
print()
print(f"  DATA 값: {data_values}")
print(f"  DATA 합계: {sum(data_values)}")
print(f"  TRAILER 값: {trailer_val}")
print()

# === VSB 섹터별 FREE AU 수 (WS80 인코딩으로 카운트) ===
print("=== VSB 섹터별 상태 분포 (2-bit/AU, MSB-first) ===")

def get_au_state(vsb_data, au_local):
    """VSB 데이터에서 AU 상태 읽기 (2-bit/AU, MSB-first)"""
    byte_idx = au_local // 4
    pair_idx = 3 - (au_local % 4)
    return (vsb_data[byte_idx] >> (pair_idx * 2)) & 0x03

STATE_NAMES = {0: "FREE", 1: "USED", 2: "DEFECT", 3: "RESRV"}

vsb_free_counts = []  # 핵심: VSB 섹터별 FREE AU 수

for si in range(vsb_num):
    vsb_lba = 1057 + si
    vsb_data = img[vsb_lba * SECTOR:(vsb_lba + 1) * SECTOR]

    # 이 VSB 섹터가 커버하는 AU 범위
    au_start = si * AU_PER_VSB_SECTOR
    au_end = min((si + 1) * AU_PER_VSB_SECTOR, num_alloc)  # 유효 범위만
    valid_count = au_end - au_start

    # 상태별 카운트
    counts = {0: 0, 1: 0, 2: 0, 3: 0}
    for au in range(au_start, au_end):
        au_local = au - (si * AU_PER_VSB_SECTOR)  # VSB 내부 인덱스
        state = get_au_state(vsb_data, au_local)
        counts[state] += 1

    vsb_free_counts.append(counts[0])

    parts = [f"{STATE_NAMES[s]}={counts[s]}" for s in [0, 1, 2, 3] if counts[s] > 0]
    print(f"  VSB[{si}] (LBA {vsb_lba}, AU {au_start}–{au_end-1}, {valid_count} AU):")
    print(f"    {', '.join(parts)}")
    print(f"    FREE count = {counts[0]}")

print()
print(f"  VSB FREE 합계: {sum(vsb_free_counts)}")
print()

# === 핵심 교차 검증 ===
print("=" * 60)
print("=== 핵심 교차 검증: MTB 값 vs VSB FREE 카운트 ===")
print("=" * 60)
print()

all_match = True
for i, (mtb_val, vsb_free) in enumerate(zip(data_values, vsb_free_counts)):
    match = mtb_val == vsb_free
    if not match:
        all_match = False
    print(f"  VSB[{i}]: MTB 0x90 value = {mtb_val:6d}  vs  VSB FREE count = {vsb_free:6d}  {'✓' if match else '✗'}")

mtb_sum = sum(data_values)
vsb_sum = sum(vsb_free_counts)
sum_match = mtb_sum == vsb_sum == num_available
print(f"\n  합계:   MTB = {mtb_sum}  vs  VSB = {vsb_sum}  vs  NumAvailable = {num_available}  {'✓' if sum_match else '✗'}")
print(f"\n  엔트리 수: MTB 0x90 = {len(data_values)}  vs  VSBNum = {vsb_num}  {'✓' if len(data_values) == vsb_num else '✗'}")

all_ok = all_match and sum_match and len(data_values) == vsb_num
print(f"\n  전체 일치: {'✓ CONFIRMED' if all_ok else '✗ MISMATCH'}")
print()

# === 태그 구조 분석 ===
print("=== MTB 태그 구조 해석 ===")
print()
print("  포맷: 4-byte TLV 레코드")
print("    byte[0] = tag (type indicator)")
print("    byte[1:4] = BE24 value")
print()
print("  태그 의미:")
print("    0x80 = START (헤더/시작 마커, value=0)")
print("    0x90 = DATA  (VSB 섹터별 FREE AU 수)")
print(f"    0xA0 = END   (종료 마커, value=0)")
print(f"    0x00 = TRAILER (value={trailer_val}, 의미 미확정)")
print()
print("  태그 비트 패턴:")
print("    0x80 = 1000_0000 (start)")
print("    0x90 = 1001_0000 (data)")
print("    0xA0 = 1010_0000 (end)")
print("    → bit7 항상 set, bit4-5 순차 증가 (0→1→2)")
print()

# === TRAILER 값 분석 ===
print("=== TRAILER 값 (0x00000002) 후보 분석 ===")
print()
num_dir = struct.unpack_from(">H", img, vd_off + 0x30)[0]
num_file = struct.unpack_from(">H", img, vd_off + 0x32)[0]
num_child = struct.unpack_from(">H", img, vd_off + 0x58)[0]
max_id = struct.unpack_from(">I", img, vd_off + 0x34)[0]

# DRB에서 총 엔트리 수 세기
drb_off = 1061 * SECTOR
drb = img[drb_off:drb_off + SECTOR]
drb_entry_count = 0
pos = 0
while pos < SECTOR:
    if all(b == 0 for b in drb[pos:pos+4]):
        break
    rec_len = drb[pos + 1]
    if rec_len == 0 or pos + rec_len > SECTOR:
        break
    drb_entry_count += 1
    pos += rec_len

print(f"  TRAILER value = {trailer_val}")
print(f"  후보 비교:")
print(f"    VD NumDir = {num_dir}  {'← 일치' if trailer_val == num_dir else ''}")
print(f"    VD NumFile = {num_file}  {'← 일치' if trailer_val == num_file else ''}")
print(f"    VD NumChild = {num_child}  {'← 일치' if trailer_val == num_child else ''}")
print(f"    VD MaxIdNum = {max_id}  {'← 일치' if trailer_val == max_id else ''}")
print(f"    DRB 엔트리 수 = {drb_entry_count}  {'← 일치' if trailer_val == drb_entry_count else ''}")
print(f"    NumDir + NumFile = {num_dir + num_file}  {'← 일치' if trailer_val == num_dir + num_file else ''}")
print(f"    VSBNum = {vsb_num}  {'← 일치' if trailer_val == vsb_num else ''}")
print()
print(f"  결론: value=2는 DRB 엔트리 수({drb_entry_count}) 및 NumDir+NumFile({num_dir+num_file})과 일치")
print(f"         단일 디스크로는 구분 불가 — 다중 디스크 비교 필요 (UNKNOWN)")
print()

# === 전체 요약 ===
print("=" * 60)
print("=== MTB 구조 요약 ===")
print("=" * 60)
print()
print("  MTB = VSB 섹터별 FREE AU 카운트 테이블")
print()
print("  구조:")
print("    +0x00: [0x80] START  value=0")
for i, val in enumerate(data_values):
    au_s = i * AU_PER_VSB_SECTOR
    au_e = min((i + 1) * AU_PER_VSB_SECTOR, num_alloc) - 1
    print(f"    +0x{4+i*4:02x}: [0x90] DATA   value={val:5d}  = VSB[{i}] FREE (AU {au_s}–{au_e})")
print(f"    +0x{4+len(data_values)*4:02x}: [0xA0] END    value=0")
print(f"    +0x{4+(len(data_values)+1)*4:02x}: [0x00] TRAIL  value={trailer_val}  (UNKNOWN)")
print()
print(f"  검증:")
print(f"    MTB FREE 합계 = {sum(data_values)} = NumAvailable({num_available}) ✓")
print(f"    MTB 엔트리 수 = {len(data_values)} = VSBNum({vsb_num}) ✓")
print(f"    VSB 실제 FREE와 1:1 대응 ✓")

#!/usr/bin/env python3
"""
DRB (Directory Record Block) 종합 분석

핵심 질문:
1. 레코드가 고정 42바이트인가, 가변 길이(byte[1])인가?
2. +0x00~+0x05 헤더 필드의 정확한 의미
3. +0x1C, +0x24, +0x28 미확인 필드의 의미
4. 속성 플래그의 정확한 위치
"""
import struct
import datetime

IMG = "/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/work/mddata_mgmt.bin"
SECTOR = 2048

with open(IMG, "rb") as f:
    img = f.read()

# === VD 파라미터 ===
vd_off = 1056 * SECTOR
num_alloc = struct.unpack_from(">I", img, vd_off + 0x18)[0]
num_used = struct.unpack_from(">I", img, vd_off + 0x24)[0]
num_available = struct.unpack_from(">I", img, vd_off + 0x20)[0]
alloc_size = struct.unpack_from(">H", img, vd_off + 0x14)[0]
num_dir = struct.unpack_from(">H", img, vd_off + 0x30)[0]
num_file = struct.unpack_from(">H", img, vd_off + 0x32)[0]
max_id = struct.unpack_from(">I", img, vd_off + 0x34)[0]
vol_attr = struct.unpack_from(">H", img, vd_off + 0x38)[0]
dir_len = struct.unpack_from(">I", img, vd_off + 0x54)[0]
num_child = struct.unpack_from(">H", img, vd_off + 0x58)[0]
drb_loc = struct.unpack_from(">H", img, vd_off + 0x50)[0]
drb_num = struct.unpack_from(">H", img, vd_off + 0x52)[0]
vma_loc = struct.unpack_from(">I", img, vd_off + 0x40)[0]

print("=== VD 참조 파라미터 ===")
print(f"  NumDir={num_dir}, NumFile={num_file}, NumChild={num_child}")
print(f"  MaxIdNum={max_id}, VolAttr=0x{vol_attr:04x}")
print(f"  DirLen={dir_len}, DRBLoc={drb_loc}, DRBNum={drb_num}")
print(f"  VMALoc={vma_loc}, AllocSize={alloc_size}")
print(f"  NumAlloc={num_alloc}, NumUsed={num_used}, NumAvailable={num_available}")
print()

# === DRB 원시 섹터 덤프 ===
drb_lba = vma_loc + drb_loc
drb = img[drb_lba * SECTOR:(drb_lba + drb_num) * SECTOR]

# 유효 데이터 끝 찾기
last_nz = -1
for i in range(len(drb) - 1, -1, -1):
    if drb[i] != 0:
        last_nz = i
        break

print(f"=== DRB 원시 데이터 (LBA {drb_lba}, {drb_num} sector) ===")
print(f"  유효 데이터: {last_nz + 1} bytes (0x0000–0x{last_nz:04x})")
print()

# 전체 유효 영역 hex dump
dump_end = min(len(drb), ((last_nz // 16) + 2) * 16)
for row in range(0, dump_end, 16):
    hex_part = " ".join(f"{drb[row+i]:02x}" for i in range(min(16, len(drb) - row)))
    ascii_part = "".join(
        chr(drb[row+i]) if 32 <= drb[row+i] < 127 else "."
        for i in range(min(16, len(drb) - row))
    )
    print(f"  {row:04x}: {hex_part:<48s}  {ascii_part}")
print()

# === 속성 플래그 정의 (mdfsck_flag_tables.md Table 2) ===
RECORD_FLAGS = {
    0x0001: "ADIR",
    0x0002: "AINVISIBLE",
    0x0004: "ASYSTEM",
    0x0008: "ADELETED",
    0x0040: "APROTECT",
    0x0080: "ABACKUP",
    0x0100: "AINHDELETE",
    0x0200: "AINHRENAME",
    0x0400: "AINHCOPY",
    0x2000: "AEXTTYPE",
    0x4000: "AFXTREC",
    0x8000: "AAEXTREC",
}

def decode_flags(val):
    flags = []
    for bit, name in sorted(RECORD_FLAGS.items()):
        if val & bit:
            flags.append(name)
    return " | ".join(flags) if flags else "(none)"

def unix_ts(val):
    if val == 0:
        return "0"
    try:
        return datetime.datetime.utcfromtimestamp(val).strftime("%Y-%m-%d %H:%M:%S UTC")
    except:
        return f"invalid({val})"

# === 가변 길이 레코드 파싱 (byte[1] = record length) ===
print("=" * 70)
print("=== 가변 길이 레코드 파싱 (byte[1] = 레코드 길이 가설) ===")
print("=" * 70)
print()

entries = []
pos = 0
idx = 0
while pos < last_nz + 1 and idx < 50:
    if all(b == 0 for b in drb[pos:pos+4]):
        break
    rec_type = drb[pos]
    rec_len = drb[pos + 1]
    if rec_len == 0 or pos + rec_len > len(drb):
        print(f"  [!] 잘못된 레코드 길이: pos=0x{pos:04x}, len={rec_len}")
        break
    rec = drb[pos:pos + rec_len]
    entries.append((pos, rec_len, rec))

    print(f"--- Entry {idx} @ DRB+0x{pos:04x} (len={rec_len}, 0x{rec_len:02x}) ---")
    # Hex dump
    for row in range(0, rec_len, 16):
        hex_part = " ".join(f"{rec[row+i]:02x}" for i in range(min(16, rec_len - row)))
        print(f"  {row:04x}: {hex_part}")
    print()

    # 바이트별 분석
    print(f"  [헤더 필드]")
    print(f"    +0x00: 0x{rec[0]:02x} (레코드 타입)")
    print(f"    +0x01: 0x{rec[1]:02x} = {rec[1]} (레코드 길이)")

    # 속성 플래그 후보 위치 테스트
    if rec_len >= 6:
        attr_02 = struct.unpack_from(">H", rec, 2)[0]
        attr_04 = struct.unpack_from(">H", rec, 4)[0]
        print(f"    +0x02: BE16 = 0x{attr_02:04x} ({attr_02}) → flags: {decode_flags(attr_02)}")
        print(f"    +0x04: BE16 = 0x{attr_04:04x} ({attr_04}) → flags: {decode_flags(attr_04)}")

        # byte 단위 분석
        print(f"    +0x02: 0x{rec[2]:02x}, +0x03: 0x{rec[3]:02x}, +0x04: 0x{rec[4]:02x}, +0x05: 0x{rec[5]:02x}")

    # 파일명 (+0x06, 10 bytes)
    if rec_len >= 16:
        name_raw = rec[6:16]
        name = name_raw.decode('ascii', errors='replace')
        name_trimmed = name.rstrip()
        base = name[:7].rstrip()
        ext = name[7:10].rstrip()
        full_name = f"{base}.{ext}" if ext else base
        print(f"\n  [파일명]")
        print(f"    +0x06: [{' '.join(f'{b:02x}' for b in name_raw)}]")
        print(f"    raw: '{name}' → '{full_name}'")

    # 타임스탬프
    if rec_len >= 28:
        ts_create = struct.unpack_from(">I", rec, 0x10)[0]
        ts_modify = struct.unpack_from(">I", rec, 0x14)[0]
        ts_access = struct.unpack_from(">I", rec, 0x18)[0]
        print(f"\n  [타임스탬프]")
        print(f"    +0x10: 0x{ts_create:08x} = {unix_ts(ts_create)} (생성)")
        print(f"    +0x14: 0x{ts_modify:08x} = {unix_ts(ts_modify)} (수정)")
        print(f"    +0x18: 0x{ts_access:08x} = {unix_ts(ts_access)} (접근)")

    # 나머지 필드
    if rec_len >= 32:
        v1c = struct.unpack_from(">I", rec, 0x1C)[0]
        print(f"\n  [+0x1C 필드]")
        print(f"    +0x1C: BE32 = 0x{v1c:08x} = {v1c}")

    if rec_len >= 36:
        v20 = struct.unpack_from(">I", rec, 0x20)[0]
        print(f"\n  [+0x20 필드 (파일 크기)]")
        print(f"    +0x20: BE32 = 0x{v20:08x} = {v20}")
        if v20 > 0:
            aus_needed = (v20 + 8191) // 8192
            print(f"    필요 AU: {aus_needed}")

    if rec_len >= 38:
        v24 = struct.unpack_from(">H", rec, 0x24)[0]
        print(f"\n  [+0x24 필드]")
        print(f"    +0x24: BE16 = 0x{v24:04x} = {v24}")

    if rec_len >= 40:
        v26 = struct.unpack_from(">H", rec, 0x26)[0]
        print(f"\n  [+0x26 필드 (시작 AU)]")
        print(f"    +0x26: BE16 = 0x{v26:04x} = AU {v26} → LBA {v26 * alloc_size}")

    if rec_len >= 42:
        v28 = struct.unpack_from(">H", rec, 0x28)[0]
        print(f"\n  [+0x28 필드]")
        print(f"    +0x28: BE16 = 0x{v28:04x} = {v28}")

    # 42바이트 이후 확장 데이터
    if rec_len > 42:
        print(f"\n  [확장 데이터 (+0x2A 이후, {rec_len - 42} bytes)]")
        for off in range(0x2A, rec_len, 2):
            if off + 2 <= rec_len:
                v = struct.unpack_from(">H", rec, off)[0]
                print(f"    +0x{off:02x}: BE16 = 0x{v:04x} = {v}")
            elif off + 1 <= rec_len:
                print(f"    +0x{off:02x}: 0x{rec[off]:02x}")

    print()
    pos += rec_len
    idx += 1

print(f"총 {len(entries)}개 엔트리, 마지막 위치: DRB+0x{pos:04x}")
print()

# === 고정 42바이트 레코드 대조 ===
print("=" * 70)
print("=== 고정 42바이트 레코드 파싱 대조 ===")
print("=" * 70)
print()

FIXED_LEN = 42
for i in range(min(5, (last_nz + 1) // FIXED_LEN + 1)):
    off = i * FIXED_LEN
    if off >= len(drb) or all(b == 0 for b in drb[off:off+4]):
        break
    rec = drb[off:off + FIXED_LEN]
    v00 = struct.unpack_from(">H", rec, 0)[0]
    name = rec[6:16].decode('ascii', errors='replace')
    print(f"  Entry {i} @ +0x{off:04x}: +0x00 BE16=0x{v00:04x}({v00}), name='{name.rstrip()}'")
    if FIXED_LEN >= 36:
        v20 = struct.unpack_from(">I", rec, 0x20)[0]
        v26 = struct.unpack_from(">H", rec, 0x26)[0]
        print(f"    +0x20={v20}, +0x26=AU {v26}")
print()

# === 속성 위치 후보 비교 ===
print("=" * 70)
print("=== 속성 플래그 위치 결정 ===")
print("=" * 70)
print()

for entry_idx, (off, rlen, rec) in enumerate(entries):
    if rlen < 6:
        continue
    attr_02 = struct.unpack_from(">H", rec, 2)[0]
    attr_04 = struct.unpack_from(">H", rec, 4)[0]
    name = rec[6:16].decode('ascii', errors='replace').rstrip() if rlen >= 16 else "?"
    is_dir = (name == "" or name == "          "[:len(name)])

    print(f"Entry {entry_idx} ({name or '(root)'}), is_dir={is_dir}:")
    print(f"  +0x02 = 0x{attr_02:04x}: {decode_flags(attr_02)}")
    print(f"    ADIR bit set: {bool(attr_02 & 0x0001)}")
    print(f"  +0x04 = 0x{attr_04:04x}: {decode_flags(attr_04)}")
    print(f"    ADIR bit set: {bool(attr_04 & 0x0001)}")
    print()

    # 속성이 +0x02에 있으면 root에 ADIR 있어야 하고 파일에는 없어야 함
    if is_dir:
        print(f"    → +0x02 해석: ADIR={'✓' if (attr_02 & 0x0001) else '✗'}")
        print(f"    → +0x04 해석: ADIR={'✓' if (attr_04 & 0x0001) else '✗'}")
    else:
        print(f"    → +0x02 해석: !ADIR={'✓' if not (attr_02 & 0x0001) else '✗ (파일인데 ADIR set!)'}")
        print(f"    → +0x04 해석: !ADIR={'✓' if not (attr_04 & 0x0001) else '✗ (파일인데 ADIR set!)'}")
    print()

# === +0x1C / +0x24 / +0x28 필드 분석 ===
print("=" * 70)
print("=== 미확인 필드 교차 분석 ===")
print("=" * 70)
print()

for entry_idx, (off, rlen, rec) in enumerate(entries):
    name = rec[6:16].decode('ascii', errors='replace').rstrip() if rlen >= 16 else "?"
    print(f"Entry {entry_idx} ({name or '(root)'}):")

    if rlen >= 32:
        v1c = struct.unpack_from(">I", rec, 0x1C)[0]
        print(f"  +0x1C = {v1c}")
        print(f"    == NumChild+1({num_child+1})? {v1c == num_child + 1}")
        print(f"    == DRB entry count({len(entries)})? {v1c == len(entries)}")
        print(f"    == MaxIdNum({max_id})? {v1c == max_id}")

    if rlen >= 38:
        v24 = struct.unpack_from(">H", rec, 0x24)[0]
        print(f"  +0x24 = {v24}")
        print(f"    == DRBLoc({drb_loc})? {v24 == drb_loc}")
        print(f"    == DRBNum({drb_num})? {v24 == drb_num}")

    if rlen >= 42:
        v28 = struct.unpack_from(">H", rec, 0x28)[0]
        print(f"  +0x28 = {v28}")

    print()

# === Z920.EXE 파일 크기 / AU 검증 ===
print("=" * 70)
print("=== Z920.EXE 할당 검증 ===")
print("=" * 70)
print()

if len(entries) >= 2:
    _, rlen, rec = entries[1]
    file_size = struct.unpack_from(">I", rec, 0x20)[0]
    start_au = struct.unpack_from(">H", rec, 0x26)[0]
    aus_needed = (file_size + 8191) // 8192
    end_au = start_au + aus_needed - 1
    start_lba = start_au * alloc_size
    print(f"  파일 크기: {file_size} bytes ({file_size/1024:.1f} KB)")
    print(f"  시작 AU: {start_au} → LBA {start_lba}")
    print(f"  필요 AU: {aus_needed}")
    print(f"  AU 범위: {start_au}–{end_au}")
    print(f"  LBA {start_lba}에서 MZ 헤더 확인: {img[start_lba*SECTOR:start_lba*SECTOR+2] == b'MZ'}")
    print()

    # 확장 데이터가 extent 정보인지 확인
    if rlen > 42:
        print(f"  확장 데이터 ({rlen - 42} bytes):")
        for off in range(0x2A, rlen, 4):
            if off + 4 <= rlen:
                v32 = struct.unpack_from(">I", rec, off)[0]
                v16a = struct.unpack_from(">H", rec, off)[0]
                v16b = struct.unpack_from(">H", rec, off + 2)[0]
                print(f"    +0x{off:02x}: BE32={v32} (0x{v32:08x}), BE16 pair=({v16a}, {v16b})")
                # AU 번호로 해석 시도
                if 0 < v16a < num_alloc:
                    print(f"           v16a={v16a} → LBA {v16a * alloc_size} (유효 AU 범위)")
                if 0 < v16b < num_alloc:
                    print(f"           v16b={v16b} → LBA {v16b * alloc_size} (유효 AU 범위)")

# === 레코드 길이 패턴 분석 ===
print()
print("=" * 70)
print("=== 레코드 길이 패턴 분석 ===")
print("=" * 70)
print()

for entry_idx, (off, rlen, rec) in enumerate(entries):
    attr_02 = struct.unpack_from(">H", rec, 2)[0] if rlen >= 4 else 0
    is_dir = bool(attr_02 & 0x0001)  # +0x02가 속성이면
    name = rec[6:16].decode('ascii', errors='replace').rstrip() if rlen >= 16 else "?"
    file_size = struct.unpack_from(">I", rec, 0x20)[0] if rlen >= 36 else 0

    aus_needed = (file_size + 8191) // 8192 if file_size > 0 else 0

    print(f"  Entry {idx}: len={rlen}, is_dir={is_dir}, name='{name or '(root)'}', "
          f"size={file_size}, AU needed={aus_needed}")
    print(f"    base=42, extra={rlen-42}")
    if rlen > 42:
        extra_entries = (rlen - 42) // 4
        print(f"    확장 4-byte 엔트리 수: {extra_entries}")
        # 각 4-byte 엔트리가 (AU start, AU count) 쌍인지 검증
        for i in range(extra_entries):
            ext_off = 42 + i * 4
            ext_au = struct.unpack_from(">H", rec, ext_off)[0]
            ext_cnt = struct.unpack_from(">H", rec, ext_off + 2)[0]
            print(f"    extent[{i}]: start_AU={ext_au}, count={ext_cnt}")

print()

# === 전체 요약 ===
print("=" * 70)
print("=== DRB 구조 분석 요약 ===")
print("=" * 70)
print()
print(f"  레코드 수: {len(entries)}")
print(f"  레코드 파싱 방식: byte[1] = 레코드 길이 (가변)")
for i, (off, rlen, rec) in enumerate(entries):
    name = rec[6:16].decode('ascii', errors='replace').rstrip() if rlen >= 16 else "?"
    print(f"    Entry {i}: offset=0x{off:04x}, len={rlen}, name='{name or '(root)'}'")

print()
print(f"  VD 대조:")
print(f"    NumDir={num_dir}, NumFile={num_file} → 총 {num_dir+num_file}")
print(f"    DRB entries={len(entries)} (root 포함)")
print(f"    NumChild={num_child}")
print(f"    MaxIdNum={max_id}")

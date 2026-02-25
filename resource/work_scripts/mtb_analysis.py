#!/usr/bin/env python3
"""
MTB (Master Table Block) 종합 분석 스크립트
============================================
- LBA 1056: VD (Volume Descriptor)
- LBA 1060: MTB (Master Table Block)
- LBA 1061: DRB (Directory Record Block)

태그+값 구조, 다양한 해석, VD/DRB 크로스레퍼런스 수행.
모든 필드는 Big-Endian으로 해석됨.
"""
import struct
import sys
import os

IMG = "/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/work/mddata_mgmt.bin"
SECTOR = 2048

# ============================================================
# 유틸리티 함수
# ============================================================
def read_sector(f, lba):
    f.seek(lba * SECTOR)
    return f.read(SECTOR)

def hexdump(data, start=0, length=None, prefix="  "):
    if length is None:
        length = len(data)
    end = min(start + length, len(data))
    for row in range(start, end, 16):
        count = min(16, end - row)
        hex_part = " ".join(f"{data[row + i]:02x}" for i in range(count))
        hex_part = hex_part.ljust(47)
        ascii_part = "".join(
            chr(data[row + i]) if 32 <= data[row + i] < 127 else "."
            for i in range(count)
        )
        print(f"{prefix}{row:04x}: {hex_part}  {ascii_part}")

def find_last_nonzero(data):
    for i in range(len(data) - 1, -1, -1):
        if data[i] != 0:
            return i
    return -1

def le16(data, off): return struct.unpack_from('<H', data, off)[0]
def le32(data, off): return struct.unpack_from('<I', data, off)[0]
def be16(data, off): return struct.unpack_from('>H', data, off)[0]
def be32(data, off): return struct.unpack_from('>I', data, off)[0]
def le24(data, off): return data[off] | (data[off+1] << 8) | (data[off+2] << 16)
def be24(data, off): return (data[off] << 16) | (data[off+1] << 8) | data[off+2]


# ============================================================
# 메인 분석
# ============================================================
with open(IMG, "rb") as f:
    img_size = os.path.getsize(IMG)
    print(f"이미지 파일: {IMG}")
    print(f"이미지 크기: {img_size} bytes ({img_size/1024/1024:.2f} MB)")
    print(f"전체 섹터 수: {img_size // SECTOR}")
    print()

    # ==========================================================
    # 1. VD (Volume Descriptor) @ LBA 1056
    # ==========================================================
    vd = read_sector(f, 1056)
    vd_last = find_last_nonzero(vd)

    print("=" * 72)
    print("  1. VD (Volume Descriptor) @ LBA 1056")
    print("=" * 72)

    show_len = min(SECTOR, ((vd_last // 16) + 2) * 16)
    print(f"\n[VD hex dump] (비어있지 않은 마지막 바이트: 0x{vd_last:04x})")
    hexdump(vd, 0, show_len)

    # VD 시그니처
    sig = vd[1:6].decode('ascii', errors='replace')
    ver = vd[6]
    print(f"\n[VD 시그니처]")
    print(f"  +0x01-0x05: '{sig}' (매직)")
    print(f"  +0x06: 0x{ver:02x} (버전={ver})")

    # 핵심 파라미터 (BE 해석)
    block_size  = be16(vd, 0x10)  # 2048
    cluster_sz  = be16(vd, 0x12)  # 32 sectors
    alloc_size  = be16(vd, 0x14)  # 4 sectors per AU

    print(f"\n[VD 핵심 파라미터] (Big-Endian)")
    print(f"  VD+0x10: BlockSize    = {block_size} bytes")
    print(f"  VD+0x12: ClusterSize  = {cluster_sz} sectors/cluster")
    print(f"  VD+0x14: AllocSize    = {alloc_size} sectors/AU")

    AU_BYTES = alloc_size * block_size  # 8192
    CLUSTER_BYTES = cluster_sz * block_size  # 65536
    print(f"  AU 크기: {AU_BYTES} bytes ({AU_BYTES/1024:.0f} KB)")
    print(f"  Cluster 크기: {CLUSTER_BYTES} bytes ({CLUSTER_BYTES/1024:.0f} KB)")

    # 볼륨 크기 필드
    num_alloc_sec  = be32(vd, 0x18)  # 17616
    num_total_sec  = be32(vd, 0x1C)  # 17616
    num_avail_sec  = be32(vd, 0x20)  # 17088
    num_used_sec   = be32(vd, 0x24)  # 272

    print(f"\n[VD 볼륨 크기 필드] (BE32)")
    print(f"  VD+0x18: NumAlloc     = {num_alloc_sec:6d} → {num_alloc_sec/alloc_size:.0f} AUs, "
          f"{num_alloc_sec*block_size/1024/1024:.2f} MB")
    print(f"  VD+0x1C: NumTotal     = {num_total_sec:6d} → {num_total_sec/alloc_size:.0f} AUs, "
          f"{num_total_sec*block_size/1024/1024:.2f} MB")
    print(f"  VD+0x20: NumAvail     = {num_avail_sec:6d} → {num_avail_sec/alloc_size:.0f} AUs, "
          f"{num_avail_sec*block_size/1024/1024:.2f} MB")
    print(f"  VD+0x24: NumRecordable= {num_used_sec:6d} → {num_used_sec/alloc_size:.0f} AUs, "
          f"{num_used_sec*block_size/1024/1024:.2f} MB")
    print(f"  검증: NumAlloc - NumAvail = {num_alloc_sec - num_avail_sec} sectors "
          f"= {(num_alloc_sec - num_avail_sec)/alloc_size:.0f} AUs (사용 중)")

    # VMA 구조 필드
    vma_loc    = be16(vd, 0x42)
    print(f"\n[VD VMA 구조 필드]")
    print(f"  VD+0x30: BE16={be16(vd,0x30):5d}  (rootDirEntries?)")
    print(f"  VD+0x32: BE16={be16(vd,0x32):5d}  (volumeSequence?)")
    print(f"  VD+0x36: BE16={be16(vd,0x36):5d}  (maxDirEntries?)")
    print(f"  VD+0x38: BE16={be16(vd,0x38):5d}  (0x82=130)")
    print(f"  VD+0x3E: BE16={be16(vd,0x3E):5d}  (0x3000=12288)")
    print(f"  VD+0x42: BE16={vma_loc:5d}  ← VMA 시작 LBA (self-ref)")
    print(f"  VD+0x44: BE16={be16(vd,0x44):5d}  (VD 복사본 수?)")
    print(f"  VD+0x46: BE16={be16(vd,0x46):5d}  (VD + VSB + ERB 길이?)")
    print(f"  VD+0x48: BE16={be16(vd,0x48):5d}  ← MTB offset → LBA {vma_loc + be16(vd,0x48)}")
    print(f"  VD+0x4A: BE16={be16(vd,0x4A):5d}  (MTB 길이 sectors)")
    print(f"  VD+0x50: BE16={be16(vd,0x50):5d}  ← DRB offset → LBA {vma_loc + be16(vd,0x50)}")
    print(f"  VD+0x52: BE16={be16(vd,0x52):5d}  (DRB 길이 sectors)")
    print(f"  VD+0x56: BE16={be16(vd,0x56):5d}  (BlockSize 반복?)")
    print(f"  VD+0x58: BE16={be16(vd,0x58):5d}")

    # 포매터 문자열
    fmt_off = vd.find(b'MDFMT')
    if fmt_off >= 0:
        fmt_end = vd.find(b'\x00', fmt_off)
        fmt_str = vd[fmt_off:fmt_end].decode('ascii', errors='replace')
        print(f"\n[포매터 ID] @ +0x{fmt_off:04x}: '{fmt_str}'")

    # 볼륨 레이블
    label_off = 0x82  # "MD DATA" 시작
    label = vd[label_off:label_off+32].split(b'\x00')[0].decode('ascii', errors='replace')
    print(f"[볼륨 레이블] @ +0x{label_off:04x}: '{label}'")

    # 타임스탬프
    print(f"\n[타임스탬프]")
    print(f"  VD+0x0280: [{' '.join(f'{vd[0x280+i]:02x}' for i in range(8))}]")

    # ==========================================================
    # 2. MTB (Master Table Block) @ LBA 1060
    # ==========================================================
    mtb = read_sector(f, 1060)
    mtb_last = find_last_nonzero(mtb)

    print("\n" + "=" * 72)
    print("  2. MTB (Master Table Block) @ LBA 1060")
    print("=" * 72)

    print(f"\n[전체 섹터 스캔]")
    print(f"  섹터 크기: {SECTOR} bytes")
    print(f"  유효 데이터: 0x0000 - 0x{mtb_last:04x} ({mtb_last + 1} bytes)")
    print(f"  0x{mtb_last+1:04x} 이후: 전부 0x00 ({SECTOR - mtb_last - 1} bytes)")

    # 0x18 이후 비어있지 않은 데이터 확인
    nonzero_after = [(i, mtb[i]) for i in range(0x18, SECTOR) if mtb[i] != 0]
    if nonzero_after:
        print(f"\n  [경고] 0x18 이후 비어있지 않은 데이터 {len(nonzero_after)}개:")
        for off, val in nonzero_after[:20]:
            print(f"    +0x{off:04x}: 0x{val:02x}")
    else:
        print(f"  0x18 이후: 전부 0x00 확인됨")

    print(f"\n[MTB hex dump]")
    hexdump(mtb, 0, min(SECTOR, ((mtb_last // 16) + 2) * 16))

    # ----------------------------------------------------------
    # 2a. 1바이트 태그 + 3바이트 값 (4바이트 레코드) 해석
    # ----------------------------------------------------------
    print("\n" + "-" * 72)
    print("  해석 A: 1바이트 태그 + 3바이트 BE24 값")
    print("-" * 72)

    tag4_records = []
    for i in range(0, min(mtb_last + 1, SECTOR), 4):
        raw = mtb[i:i+4]
        if any(b != 0 for b in raw):
            tag = mtb[i]
            val_be = be24(mtb, i + 1)
            val_le = le24(mtb, i + 1)
            tag4_records.append((i, tag, val_be, val_le, raw))
            print(f"  +0x{i:04x}: tag=0x{tag:02x}  BE24={val_be:8d}(0x{val_be:06x})  "
                  f"LE24={val_le:8d}(0x{val_le:06x})  [{' '.join(f'{b:02x}' for b in raw)}]")

    # ----------------------------------------------------------
    # 2b. 2바이트 태그+sub + 2바이트 BE16 값 해석
    # ----------------------------------------------------------
    print("\n" + "-" * 72)
    print("  해석 B: 1바이트 태그 + 1바이트 sub + BE16 값 (★ 유력 해석)")
    print("-" * 72)

    tag2v2_records = []
    for i in range(0, min(mtb_last + 4, SECTOR), 4):
        raw = mtb[i:i+4]
        if any(b != 0 for b in raw):
            tag = mtb[i]
            sub = mtb[i+1]
            val_be16 = be16(mtb, i + 2)
            val_le16 = le16(mtb, i + 2)
            tag2v2_records.append((i, tag, sub, val_be16))
            print(f"  +0x{i:04x}: tag=0x{tag:02x} sub=0x{sub:02x}  "
                  f"BE16={val_be16:6d}(0x{val_be16:04x})  "
                  f"LE16={val_le16:6d}(0x{val_le16:04x})  "
                  f"[{' '.join(f'{b:02x}' for b in raw)}]")

    # ----------------------------------------------------------
    # 2c. 2바이트 태그 + 2바이트 값 해석
    # ----------------------------------------------------------
    print("\n" + "-" * 72)
    print("  해석 C: BE16 태그 + BE16 값")
    print("-" * 72)

    for i in range(0, min(mtb_last + 4, SECTOR), 4):
        raw = mtb[i:i+4]
        if any(b != 0 for b in raw):
            tag_be = be16(mtb, i)
            val_be = be16(mtb, i + 2)
            print(f"  +0x{i:04x}: tag_BE=0x{tag_be:04x}  val_BE={val_be:6d}(0x{val_be:04x})  "
                  f"[{' '.join(f'{b:02x}' for b in raw)}]")

    # ----------------------------------------------------------
    # 2d. 순수 4바이트 LE32/BE32 해석
    # ----------------------------------------------------------
    print("\n" + "-" * 72)
    print("  해석 D: 순수 BE32/LE32")
    print("-" * 72)

    for i in range(0, min(mtb_last + 4, SECTOR), 4):
        raw = mtb[i:i+4]
        if any(b != 0 for b in raw):
            val_be = be32(mtb, i)
            val_le = le32(mtb, i)
            print(f"  +0x{i:04x}: BE32={val_be:10d}(0x{val_be:08x})  "
                  f"LE32={val_le:10d}(0x{val_le:08x})")

    # ----------------------------------------------------------
    # 2e. 1+1 바이트 레코드 해석
    # ----------------------------------------------------------
    print("\n" + "-" * 72)
    print("  해석 E: 1바이트 태그 + 1바이트 값 (2바이트 레코드)")
    print("-" * 72)

    for i in range(0, min(mtb_last + 2, SECTOR), 2):
        raw = mtb[i:i+2]
        if any(b != 0 for b in raw):
            print(f"  +0x{i:04x}: [{raw[0]:02x} {raw[1]:02x}]  "
                  f"tag=0x{raw[0]:02x} val={raw[1]:3d}(0x{raw[1]:02x})")

    # ==========================================================
    # 3. MTB BE16 값의 다양한 해석
    # ==========================================================
    print("\n" + "=" * 72)
    print("  3. MTB BE16 값의 다양한 해석")
    print("=" * 72)

    # 핵심 BE16 값: 7664, 8192, 1232 (tag=0x90의 3개 값)
    mtb_vals = {
        (0x04, 0x90): ("BE16", be16(mtb, 0x06)),
        (0x08, 0x90): ("BE16", be16(mtb, 0x0A)),
        (0x0C, 0x90): ("BE16", be16(mtb, 0x0E)),
    }

    for (off, tag), (label, val) in sorted(mtb_vals.items()):
        if val == 0:
            continue
        print(f"\n  MTB+0x{off:04x} tag=0x{tag:02x}: {label}={val} (0x{val:04x})")
        print(f"    [AU 번호로 해석]")
        print(f"      AU#{val} → LBA {val * alloc_size}, "
              f"byte offset 0x{val * AU_BYTES:08x} ({val * AU_BYTES / 1024 / 1024:.3f} MB)")
        print(f"    [섹터(LBA) 번호로 해석]")
        print(f"      LBA {val} → AU#{val // alloc_size} (나머지 {val % alloc_size}), "
              f"byte offset {val * block_size} ({val * block_size / 1024 / 1024:.3f} MB)")
        print(f"    [블록 카운트로 해석]")
        print(f"      {val} blocks → {val * block_size / 1024 / 1024:.3f} MB")
        print(f"    [AllocSize 곱/나눗셈]")
        print(f"      *{alloc_size} = {val * alloc_size}")
        print(f"      /{alloc_size} = {val / alloc_size:.2f}")
        print(f"    [ClusterSize 곱/나눗셈]")
        print(f"      *{cluster_sz} = {val * cluster_sz}")
        print(f"      /{cluster_sz} = {val / cluster_sz:.4f}")
        print(f"    [BlockSize 곱]")
        print(f"      *{block_size} = {val * block_size} ({val * block_size / 1024 / 1024:.3f} MB)")

    # ----------------------------------------------------------
    # 3a. 핵심 관계 분석
    # ----------------------------------------------------------
    v_7664 = be16(mtb, 0x06)
    v_8192 = be16(mtb, 0x0A)
    v_1232 = be16(mtb, 0x0E)

    print("\n" + "-" * 72)
    print("  3a. MTB 값 간 관계 분석")
    print("-" * 72)
    print(f"\n  값: A=0x1DF0({v_7664}), B=0x2000({v_8192}), C=0x04D0({v_1232})")
    print(f"  A + C = {v_7664 + v_1232}")
    print(f"  B - A = {v_8192 - v_7664} (= 528)")
    print(f"  B - C = {v_8192 - v_1232}")
    print(f"  A - C = {v_7664 - v_1232}")
    print(f"  A / B = {v_7664 / v_8192:.6f}")
    print(f"  C / B = {v_1232 / v_8192:.6f}")
    print(f"  C / A = {v_1232 / v_7664:.6f}")
    print()
    print(f"  ★ B(8192) = A(7664) + 528")
    print(f"  ★ 8192 AUs * {AU_BYTES} bytes = {v_8192 * AU_BYTES / 1024 / 1024:.0f} MB = MD DATA 디스크 전체 용량")
    print(f"  ★ B - A = 528 → 528 AUs = {528 * AU_BYTES / 1024 / 1024:.3f} MB (사용 중)")
    print(f"  ★ C(1232) AUs = {v_1232 * AU_BYTES / 1024 / 1024:.3f} MB")

    # ----------------------------------------------------------
    # 3b. 마지막 4바이트 특별 분석 (00 00 00 02)
    # ----------------------------------------------------------
    print("\n" + "-" * 72)
    print("  3b. 마지막 4바이트 특별 분석")
    print("-" * 72)

    last4_off = 0x14
    last4 = mtb[last4_off:last4_off+4]
    print(f"\n  MTB+0x{last4_off:04x}: [{' '.join(f'{b:02x}' for b in last4)}]")
    print(f"    tag+sub=0x{mtb[0x10]:02x} 0x{mtb[0x11]:02x} (0xA0 0x00 = 종료 마커?)")
    print(f"    그 다음 4바이트: [{' '.join(f'{b:02x}' for b in last4)}]")
    print(f"    BE32 = {be32(mtb, last4_off)} → 파티션/볼륨 번호 2?")
    print(f"    BE16 쌍: ({be16(mtb, last4_off)}, {be16(mtb, last4_off+2)})")
    print(f"    또는 tag=0x00 sub=0x00 BE16={be16(mtb, last4_off+2)} → 값 2")

    # '00 00 00 02' 패턴 검색
    print(f"\n  '00 00 00 02' 패턴 전체 검색:")
    for off in range(0, mtb_last + 1):
        if off + 4 <= len(mtb) and mtb[off:off+4] == bytes([0x00, 0x00, 0x00, 0x02]):
            print(f"    발견 @ +0x{off:04x}")

    # ==========================================================
    # 4. DRB (Directory Record Block) @ LBA 1061
    # ==========================================================
    drb = read_sector(f, 1061)
    drb_last = find_last_nonzero(drb)

    print("\n" + "=" * 72)
    print("  4. DRB (Directory Record Block) @ LBA 1061")
    print("=" * 72)

    print(f"\n  유효 데이터: 0x0000 - 0x{drb_last:04x} ({drb_last + 1} bytes)")

    print(f"\n[DRB hex dump]")
    hexdump(drb, 0, min(SECTOR, ((drb_last // 16) + 2) * 16))

    # 가변 길이 레코드 파싱 (byte[1] = 레코드 전체 길이)
    print(f"\n[DRB 가변 길이 레코드 파싱]")
    pos = 0
    entry_idx = 0
    drb_entries = []

    while pos < drb_last and entry_idx < 20:
        if all(b == 0 for b in drb[pos:pos+4]):
            break
        rec_len = drb[pos + 1]
        if rec_len == 0 or pos + rec_len > SECTOR:
            break
        rec = drb[pos:pos + rec_len]
        drb_entries.append((pos, rec))

        print(f"\n  --- DRB 엔트리 {entry_idx} @ +0x{pos:04x} (길이={rec_len}) ---")
        hexdump(drb, pos, rec_len, prefix="    ")

        # 필드 해석
        print(f"    +0x00: 0x{rec[0]:02x} (레코드 유형)")
        print(f"    +0x01: 0x{rec[1]:02x} ({rec[1]}) (레코드 길이)")
        print(f"    +0x02: 0x{rec[2]:02x} (속성 바이트 1)")
        print(f"    +0x03: 0x{rec[3]:02x} (속성 바이트 2)")
        print(f"    +0x04: 0x{rec[4]:02x} (속성 바이트 3)")
        print(f"    +0x05: 0x{rec[5]:02x} (속성 바이트 4)")

        # 이름 (8.3 형식, +0x06-0x0F)
        name_raw = rec[6:16]
        name = name_raw.decode('ascii', errors='replace').rstrip()
        print(f"    +0x06-0x0F: 이름 = '{name}'")

        # 타임스탬프 (BE32, Unix epoch?)
        if len(rec) > 0x13:
            ts1 = be32(rec, 0x10)
            print(f"    +0x10: BE32=0x{ts1:08x} ({ts1}) (생성 타임스탬프)")
        if len(rec) > 0x17:
            ts2 = be32(rec, 0x14)
            print(f"    +0x14: BE32=0x{ts2:08x} ({ts2}) (수정 타임스탬프)")
        if len(rec) > 0x1B:
            ts3 = be32(rec, 0x18)
            print(f"    +0x18: BE32=0x{ts3:08x} ({ts3}) (접근 타임스탬프)")

        # 크기/AU 필드
        if len(rec) > 0x1D:
            print(f"    +0x1C: BE16={be16(rec, 0x1C):5d} (0x{be16(rec, 0x1C):04x})")
        if len(rec) > 0x1F:
            print(f"    +0x1E: BE16={be16(rec, 0x1E):5d} (0x{be16(rec, 0x1E):04x})")
        if len(rec) > 0x23:
            v20 = be32(rec, 0x20)
            print(f"    +0x20: BE32={v20:10d} (0x{v20:08x}) ← 파일 크기 또는 디렉터리 크기?")
        if len(rec) > 0x25:
            print(f"    +0x24: BE16={be16(rec, 0x24):5d} (0x{be16(rec, 0x24):04x})")
        if len(rec) > 0x27:
            v26 = be16(rec, 0x26)
            print(f"    +0x26: BE16={v26:5d} (0x{v26:04x}) ← 시작 AU?")

        # 추가 필드 (긴 레코드의 경우)
        if len(rec) > 0x29:
            for j in range(0x28, len(rec), 2):
                if j + 2 <= len(rec):
                    v = be16(rec, j)
                    if v != 0:
                        print(f"    +0x{j:02x}: BE16={v:5d} (0x{v:04x})")

        pos += rec_len
        entry_idx += 1

    # DRB 핵심 값 요약
    print(f"\n  --- DRB 핵심 값 요약 ---")
    if len(drb_entries) >= 1:
        _, e0 = drb_entries[0]
        print(f"  엔트리 0 (루트 디렉터리):")
        print(f"    레코드 길이: {e0[1]}")
        if len(e0) > 0x27:
            print(f"    +0x1E: BE16={be16(e0,0x1E):5d} (0x{be16(e0,0x1E):04x})")
            print(f"    +0x20: BE32={be32(e0,0x20):10d} → 디렉터리 크기?")
            print(f"    +0x24: BE16={be16(e0,0x24):5d} (0x{be16(e0,0x24):04x})")
            print(f"    +0x26: BE16={be16(e0,0x26):5d} (0x{be16(e0,0x26):04x}) → 시작 AU?")

    if len(drb_entries) >= 2:
        _, e1 = drb_entries[1]
        print(f"\n  엔트리 1 (Z920.EXE):")
        print(f"    레코드 길이: {e1[1]}")
        if len(e1) > 0x23:
            file_size = be32(e1, 0x20)
            print(f"    +0x20: BE32={file_size:10d} → 파일 크기?")
        if len(e1) > 0x25:
            start_au = be16(e1, 0x24)
            print(f"    +0x24: BE16={start_au:5d} (0x{start_au:04x}) → 시작 AU?")
        if len(e1) > 0x27:
            v26 = be16(e1, 0x26)
            print(f"    +0x26: BE16={v26:5d} (0x{v26:04x})")

        # 파일 크기 계산
        if len(e1) > 0x23:
            fsize = be32(e1, 0x20)
            if 0 < fsize < 200 * 1024 * 1024:  # 합리적 범위
                aus_needed = (fsize + AU_BYTES - 1) // AU_BYTES
                print(f"    파일 크기: {fsize} bytes ({fsize/1024:.1f} KB)")
                print(f"    필요 AU 수: {aus_needed}")
            else:
                print(f"    +0x20 BE32={fsize} → 파일 크기로는 비합리적")
                # 다른 오프셋 시도
                for try_off in [0x1E, 0x22, 0x24]:
                    if try_off + 4 <= len(e1):
                        v = be32(e1, try_off)
                        if 0 < v < 200 * 1024 * 1024:
                            print(f"    대안: +0x{try_off:02x} BE32={v} ({v/1024:.1f} KB)")

    # ==========================================================
    # 5. MTB ↔ VD 크로스 레퍼런스
    # ==========================================================
    print("\n" + "=" * 72)
    print("  5. MTB ↔ VD 크로스 레퍼런스")
    print("=" * 72)

    print(f"\n  MTB BE16 값들:")
    print(f"    tag=0x90: 0x1DF0 = {v_7664}")
    print(f"    tag=0x90: 0x2000 = {v_8192}")
    print(f"    tag=0x90: 0x04D0 = {v_1232}")
    print(f"\n  VD BE32 값들:")
    print(f"    NumAlloc:      {num_alloc_sec} sectors = {num_alloc_sec//alloc_size} AUs")
    print(f"    NumTotal:      {num_total_sec} sectors = {num_total_sec//alloc_size} AUs")
    print(f"    NumAvail:      {num_avail_sec} sectors = {num_avail_sec//alloc_size} AUs")
    print(f"    NumRecordable: {num_used_sec} sectors = {num_used_sec//alloc_size} AUs")

    # 비교
    print(f"\n  [직접 매칭]")
    vd_au_vals = {
        "NumAlloc":  num_alloc_sec // alloc_size,
        "NumTotal":  num_total_sec // alloc_size,
        "NumAvail":  num_avail_sec // alloc_size,
        "NumRecordable": num_used_sec // alloc_size,
    }
    for name, vd_au in vd_au_vals.items():
        for mtb_label, mtb_val in [("0x1DF0", v_7664), ("0x2000", v_8192), ("0x04D0", v_1232)]:
            if mtb_val == vd_au:
                print(f"    MTB {mtb_label}({mtb_val}) == VD {name} ({vd_au} AUs)")

    print(f"\n  [곱/나눗셈 매칭]")
    for mtb_label, mtb_val in [("0x1DF0", v_7664), ("0x2000", v_8192), ("0x04D0", v_1232)]:
        for name, vd_sec in [("NumAlloc", num_alloc_sec), ("NumAvail", num_avail_sec),
                              ("NumRecordable", num_used_sec)]:
            if mtb_val * alloc_size == vd_sec:
                print(f"    MTB {mtb_label}({mtb_val}) * AllocSize({alloc_size}) "
                      f"= VD {name}({vd_sec}) ← MTB는 AU 단위!")
            if vd_sec != 0 and mtb_val == vd_sec * alloc_size:
                print(f"    MTB {mtb_label}({mtb_val}) = VD {name}({vd_sec}) * AllocSize({alloc_size})")

    # VD NumAlloc-NumAvail = 528 vs MTB 8192-7664 = 528
    diff_vd = num_alloc_sec - num_avail_sec
    diff_mtb = v_8192 - v_7664
    print(f"\n  [차이값 매칭]")
    print(f"    VD NumAlloc - NumAvail = {diff_vd} sectors = {diff_vd//alloc_size} AUs")
    print(f"    MTB 0x2000 - 0x1DF0 = {diff_mtb}")
    if diff_mtb * alloc_size == diff_vd:
        print(f"    ★ MTB 차이({diff_mtb}) * AllocSize({alloc_size}) = VD 차이({diff_vd}) → 일치!")
    if diff_mtb == diff_vd:
        print(f"    ★ MTB 차이({diff_mtb}) == VD 차이({diff_vd}) → 동일 단위!")

    # ==========================================================
    # 6. MTB ↔ DRB 크로스 레퍼런스
    # ==========================================================
    print("\n" + "=" * 72)
    print("  6. MTB ↔ DRB 크로스 레퍼런스")
    print("=" * 72)

    if len(drb_entries) >= 2:
        _, e1 = drb_entries[1]
        # 엔트리 1의 여러 BE16/BE32 값들과 MTB 매칭
        print(f"\n  DRB 엔트리 1 (Z920.EXE) 값들:")
        for off in range(0, len(e1) - 1, 2):
            v16 = be16(e1, off)
            if v16 == 0:
                continue
            for mtb_label, mtb_val in [("0x1DF0", v_7664), ("0x2000", v_8192), ("0x04D0", v_1232), ("528", 528)]:
                if v16 == mtb_val:
                    print(f"    DRB+0x{off:02x} BE16={v16} == MTB {mtb_label}")
                if mtb_val != 0 and v16 != 0:
                    if v16 * alloc_size == mtb_val:
                        print(f"    DRB+0x{off:02x} BE16={v16} * {alloc_size} = MTB {mtb_label}({mtb_val})")
                    if v16 == mtb_val * alloc_size:
                        print(f"    DRB+0x{off:02x} BE16={v16} = MTB {mtb_label}({mtb_val}) * {alloc_size}")

    # ==========================================================
    # 7. AU 공간 범위 매핑
    # ==========================================================
    print("\n" + "=" * 72)
    print("  7. AU 공간 범위 매핑")
    print("=" * 72)

    # MTB 해석: 전체=8192 AUs, 가용=7664 AUs, 사용=528 AUs
    # 이 값들이 AU 단위라면:
    print(f"\n  [시나리오 1: MTB 값 = AU 수]")
    print(f"    NumAlloc    = 8192 AUs = {8192 * AU_BYTES / 1024 / 1024:.0f} MB")
    print(f"    NumFree     = 7664 AUs = {7664 * AU_BYTES / 1024 / 1024:.2f} MB")
    print(f"    NumUsed     = 528 AUs  = {528 * AU_BYTES / 1024 / 1024:.2f} MB")
    print(f"    0x04D0(1232)= 1232 AUs = {1232 * AU_BYTES / 1024 / 1024:.2f} MB")
    print(f"    예약 (Reserved): AU 0-255 (256 AU, 2 MB)")
    print(f"    사용 (Used):     AU 256-783 (528 AU, 4.125 MB)")
    print(f"    여유 (Free):     AU 784-8191 (7408 AU, 57.875 MB)")
    print(f"    ※ NumFree(7664) ≠ 8192-528(7664)? → 7664 = 8192 - 528 ✓")

    print(f"\n  [시나리오 2: MTB 값 = 섹터 수]")
    print(f"    NumAlloc     = 8192 sectors → 2048 AUs = 16 MB")
    print(f"    NumFree      = 7664 sectors → 1916 AUs = 14.97 MB")
    print(f"    NumUsed(diff)= 528 sectors  → 132 AUs  = 1.03 MB")
    print(f"    0x04D0(1232) = 1232 sectors → 308 AUs  = 2.41 MB")

    print(f"\n  [시나리오 3: MTB 값 = AU, VD는 AU와 직접 비교]")
    print(f"    VD NumAlloc(AUs) = {num_alloc_sec//alloc_size}")
    print(f"    VD NumAvail(AUs) = {num_avail_sec//alloc_size}")
    print(f"    VD Used(AUs)     = {(num_alloc_sec-num_avail_sec)//alloc_size}")
    print(f"    MTB NumAlloc     = {v_8192}")
    print(f"    → VD와 MTB 단위 비교: VD {num_alloc_sec//alloc_size} AUs vs MTB {v_8192} AUs")
    print(f"    → MTB가 디스크 전체, VD가 데이터 파티션?")

    # ==========================================================
    # 8. 태그 바이트 패턴 분석
    # ==========================================================
    print("\n" + "=" * 72)
    print("  8. 태그 바이트 패턴 분석")
    print("=" * 72)

    tags = [(mtb[i], i) for i in range(0, mtb_last + 1, 4) if any(mtb[j] != 0 for j in range(i, min(i+4, mtb_last+1)))]
    print(f"\n  태그 시퀀스: {[f'0x{t:02x}@+0x{o:02x}' for t, o in tags]}")

    print(f"\n  비트 분석:")
    seen_tags = set()
    for t, o in tags:
        if t not in seen_tags:
            print(f"    0x{t:02x} = {t:08b}  상위4={t>>4:x}  하위4={t&0xf:x}")
            seen_tags.add(t)

    print(f"\n  태그 간 차이:")
    for i in range(1, len(tags)):
        diff = tags[i][0] - tags[i-1][0]
        print(f"    0x{tags[i-1][0]:02x} → 0x{tags[i][0]:02x}: diff = {diff} (0x{diff & 0xFF:02x})")

    print(f"\n  ★ 패턴: 0x80(시작?), 0x90 x3(데이터), 0xA0(종료?), 0x00(트레일러)")
    print(f"  ★ 태그 상위 비트: 8=1000, 9=1001, A=1010 → bit 7 항상 set, bit 4-5 증가")

    # ==========================================================
    # 9. 종합 요약
    # ==========================================================
    print("\n" + "=" * 72)
    print("  9. 종합 요약 및 결론")
    print("=" * 72)

    print(f"""
  MTB 섹터 (LBA 1060):
    유효 데이터: 24 bytes (0x0000 - 0x0017), 나머지 2024 bytes = 0x00

  MTB 구조 (tag=1 byte, sub=1 byte, value=BE16):
    +0x00: [0x80 0x00] value=0x0000 (   0) → 시작 마커 / MTB 헤더
    +0x04: [0x90 0x00] value=0x1DF0 (7664) → NumFree AUs (가용 AU 수)
    +0x08: [0x90 0x00] value=0x2000 (8192) → NumAlloc AUs (전체 AU 수)
    +0x0C: [0x90 0x00] value=0x04D0 (1232) → ??? (추가 분석 필요)
    +0x10: [0xA0 0x00] value=0x0000 (   0) → 종료 마커 / 섹션 구분
    +0x14: [0x00 0x00] value=0x0002 (   2) → 볼륨 번호? 또는 트레일러

  핵심 관계:
    MTB NumAlloc(8192) - MTB NumFree(7664) = 528 AUs (사용 중)
    VD  NumAlloc - NumAvail = 528 sectors = 132 AUs (사용 중 sectors)
    MTB 528 AUs * AllocSize(4) = 2112 sectors
    ↓
    MTB와 VD의 "사용 중" 차이(528)는 같지만 단위가 다를 수 있음
    (MTB=AU 단위, VD=sector 단위 가능성 또는 둘 다 같은 단위)

  디스크 크기:
    MTB 8192 AUs * 8 KB/AU = 64 MB (MD DATA 표준 용량)

  VD 핵심 파라미터:
    BlockSize=2048, ClusterSize=32 sectors, AllocSize=4 sectors/AU
    VMA 시작 LBA=1056, MTB @ LBA 1060, DRB @ LBA 1061

  DRB:
    엔트리 0: 루트 디렉터리 (42 bytes)
    엔트리 1: Z920.EXE (58 bytes)
    레코드 형식: byte[0]=타입, byte[1]=전체 길이, byte[6:16]=8.3 이름
""")

    print("분석 완료.")


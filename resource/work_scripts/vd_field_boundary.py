#!/usr/bin/env python3
"""
VD 0x28-0x5A 영역 필드 경계 검증

방법론:
1. WS19 mdfsck emit map → 필드 이름 + 글로벌 주소 순서
2. WS37 endian normalization → 글로벌 주소에 on-disk offset = global - 0x5b30
3. WS36 xref gaps → 미참조 글로벌 = reserved/padding
4. WS78 live media hex → 실측값으로 교차 검증
"""
import struct

IMG = "/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/work/mddata_mgmt.bin"
SECTOR = 2048
VD_LBA = 1056


def be16(data, off):
    return struct.unpack_from(">H", data, off)[0]


def be32(data, off):
    return struct.unpack_from(">I", data, off)[0]


# WS19/WS21에서 도출한 필드 맵 (global → on-disk = global - 0x5b30)
# WS36 xref 분석으로 u16 vs u32 판별, gap 식별
FIELD_MAP = [
    # (on-disk offset, size, field name, format spec)
    # === 0x10-0x27: 이미 CONFIRMED ===
    (0x10, 2, "BlockSize",       "%d"),
    (0x12, 2, "ClusterSize",     "%d"),
    (0x14, 2, "AllocSize",       "%d"),
    (0x16, 2, "(reserved)",      None),
    (0x18, 4, "NumAlloc",        "%ld"),
    (0x1C, 4, "NumRecordable",   "%ld"),
    (0x20, 4, "NumAvailable",    "%ld"),
    (0x24, 4, "NumUsed",         "%ld"),
    # === 0x28-0x5A: 규명 대상 ===
    (0x28, 4, "NumDefective",    "%d"),   # WS36: 0x5b58/0x5b5a u32 pair, mdfsck는 low u16만 사용
    (0x2C, 4, "(reserved)",      None),   # WS36: 0x5b5c-0x5b5f xref 없음
    (0x30, 2, "NumDir",          "%d"),
    (0x32, 2, "NumFile",         "%d"),
    (0x34, 4, "MaxIdNum",        "%d"),   # WS36: 0x5b64/0x5b66 u32 pair, mdfsck는 low u16만 사용
    (0x38, 2, "VolAttr",         "%04x"),
    (0x3A, 2, "(reserved)",      None),   # WS36: 0x5b6a xref 없음
    (0x3C, 4, "VMALen",          "%ld"),
    (0x40, 4, "VMALoc",          "%ld"),
    (0x44, 2, "VSBLoc",          "%d"),
    (0x46, 2, "VSBNum",          "%d"),
    (0x48, 2, "MTBLoc",          "%d"),
    (0x4A, 2, "MTBNum",          "%d"),
    (0x4C, 2, "ERBLoc",          "%d"),
    (0x4E, 2, "ERBNum",          "%d"),
    (0x50, 2, "DRBLoc",          "%d"),
    (0x52, 2, "DRBNum",          "%d"),
    (0x54, 4, "DirLen",          "%ld"),
    (0x58, 2, "NumChild",        "%d"),
]


def main():
    with open(IMG, "rb") as f:
        f.seek(VD_LBA * SECTOR)
        vd = f.read(SECTOR)

    print("=== VD 0x28–0x5A 필드 경계 검증 ===")
    print()
    print("매핑 근거: on-disk offset = mdfsck global addr - 0x5b30")
    print("  (WS37 rep movsw 복사 목적지 = 0x5b30, WS36 xref로 gap 식별)")
    print()

    # 1) 전체 hex dump (0x28-0x5A)
    print("--- Raw hex (0x28–0x5A) ---")
    for row in range(0x28, 0x60, 16):
        end = min(row + 16, 0x60)
        hex_part = " ".join(f"{vd[row+i]:02x}" for i in range(end - row))
        ascii_part = "".join(
            chr(vd[row+i]) if 32 <= vd[row+i] < 127 else "."
            for i in range(end - row)
        )
        print(f"  {row:04x}: {hex_part:<48s}  {ascii_part}")
    print()

    # 2) 필드별 파싱 (0x28-0x5A)
    print("--- 필드별 파싱 결과 ---")
    print(f"{'Offset':<8s} {'Size':>4s} {'Field':<16s} {'Global':<14s} {'Raw Hex':<14s} {'Value':<12s} {'검증'}")
    print("-" * 90)

    for off, sz, name, fmt in FIELD_MAP:
        if off < 0x28:
            continue
        if off > 0x58:
            break

        global_addr = off + 0x5b30
        if sz == 2:
            val = be16(vd, off)
            raw = f"{vd[off]:02x} {vd[off+1]:02x}"
            global_str = f"0x{global_addr:04x}"
        elif sz == 4:
            val = be32(vd, off)
            raw = f"{vd[off]:02x} {vd[off+1]:02x} {vd[off+2]:02x} {vd[off+3]:02x}"
            global_str = f"0x{global_addr:04x}/0x{global_addr+2:04x}"
        else:
            continue

        # 교차 검증 메모
        note = ""
        if name == "NumDefective" and val == 0:
            note = "✓ 포맷 직후 정상"
        elif name == "NumDir" and val == 1:
            note = "✓ 루트 1개 (DRB entry 0)"
        elif name == "NumFile" and val == 1:
            note = "✓ Z920.EXE 1개 (DRB entry 1)"
        elif name == "MaxIdNum":
            note = f"= {val} (다음 할당 ID)"
        elif name == "VolAttr":
            note = f"= 0x{val:04x}"
        elif name == "VMALen":
            note = f"= {val} AU (관리영역 크기)"
        elif name == "VMALoc":
            if val == VD_LBA:
                note = f"✓ = LBA {val} (VD 자기참조)"
            else:
                note = f"= LBA {val}"
        elif name == "VSBLoc":
            target_lba = VD_LBA + val
            note = f"→ VMA+{val} = LBA {target_lba}"
            if target_lba == 1057:
                note += " ✓ (VSB 비트맵)"
        elif name == "VSBNum":
            note = f"= {val} 섹터"
        elif name == "MTBLoc":
            target_lba = VD_LBA + val
            note = f"→ VMA+{val} = LBA {target_lba}"
            if target_lba == 1060:
                note += " ✓ (MTB)"
        elif name == "MTBNum":
            note = f"= {val} 섹터"
        elif name == "ERBLoc":
            if val > 0:
                note = f"→ VMA+{val} = LBA {VD_LBA + val}"
            else:
                note = "= 0 (ERB 없음?)"
        elif name == "ERBNum":
            note = f"= {val} 섹터"
        elif name == "DRBLoc":
            target_lba = VD_LBA + val
            note = f"→ VMA+{val} = LBA {target_lba}"
            if target_lba == 1061:
                note += " ✓ (DRB)"
        elif name == "DRBNum":
            note = f"= {val} 섹터"
        elif name == "DirLen":
            note = f"= {val} bytes (디렉토리 총 크기)"
        elif name == "NumChild":
            note = f"= {val} (루트 하위 엔트리 수)"
        elif name == "(reserved)":
            if val == 0:
                note = "✓ zero (패딩)"
            else:
                note = f"⚠ non-zero reserved: {val}"

        print(f"  0x{off:02x}   {sz:>4d} {name:<16s} {global_str:<14s} {raw:<14s} {val:<12d} {note}")

    print()

    # 3) 위치 참조 크로스체크
    print("--- 위치 참조 크로스체크 ---")
    vsb_loc = be16(vd, 0x44)
    mtb_loc = be16(vd, 0x48)
    erb_loc = be16(vd, 0x4C)
    drb_loc = be16(vd, 0x50)
    vma_loc = be32(vd, 0x40)

    print(f"VMA 시작 LBA: {vma_loc} (= VD LBA {VD_LBA})")
    print(f"VSB: VMA+{vsb_loc} = LBA {vma_loc + vsb_loc} (비트맵, LBA 1057 확인)")
    print(f"MTB: VMA+{mtb_loc} = LBA {vma_loc + mtb_loc} (MTB, LBA 1060 확인)")
    if erb_loc > 0:
        print(f"ERB: VMA+{erb_loc} = LBA {vma_loc + erb_loc}")
    else:
        print(f"ERB: loc=0 (이 디스크에 ERB 없음)")
    print(f"DRB: VMA+{drb_loc} = LBA {vma_loc + drb_loc} (DRB, LBA 1061 확인)")
    print()

    # 4) VMALen 검증
    vma_len = be32(vd, 0x3C)
    alloc_size = be16(vd, 0x14)
    print(f"VMALen: {vma_len} AU = {vma_len * alloc_size} 섹터 = {vma_len * alloc_size * 2048} bytes")
    print(f"  VMA 범위: LBA {vma_loc} – {vma_loc + vma_len * alloc_size - 1}")
    print()

    # 5) 글로벌 주소 연속성 검증
    print("--- 글로벌 주소 연속성 검증 ---")
    print("WS36 xref 기반 사용 글로벌 (0x5b58–0x5b88):")
    used_globals = [
        (0x5b58, "NumDefective lo"),
        (0x5b5a, "NumDefective hi"),
        # 0x5b5c, 0x5b5e: gap
        (0x5b60, "NumDir"),
        (0x5b62, "NumFile"),
        (0x5b64, "MaxIdNum lo"),
        (0x5b66, "MaxIdNum hi"),
        (0x5b68, "VolAttr"),
        # 0x5b6a: gap
        (0x5b6c, "VMALen lo"),
        (0x5b6e, "VMALen hi"),
        (0x5b70, "VMALoc lo"),
        (0x5b72, "VMALoc hi"),
        (0x5b74, "VSBLoc"),
        (0x5b76, "VSBNum"),
        (0x5b78, "MTBLoc"),
        (0x5b7a, "MTBNum"),
        (0x5b7c, "ERBLoc"),
        (0x5b7e, "ERBNum"),
        (0x5b80, "DRBLoc"),
        (0x5b82, "DRBNum"),
        (0x5b84, "DirLen lo"),
        (0x5b86, "DirLen hi"),
        (0x5b88, "NumChild"),
    ]
    for gaddr, label in used_globals:
        disk_off = gaddr - 0x5b30
        disk_val = be16(vd, disk_off)
        print(f"  0x{gaddr:04x} → disk 0x{disk_off:02x} = 0x{disk_val:04x} ({disk_val:5d})  {label}")

    print()
    print("Gap 위치 (WS36 xref 없음):")
    gaps = [(0x5b46, 0x16), (0x5b5c, 0x2C), (0x5b5e, 0x2E), (0x5b6a, 0x3A)]
    for gaddr, doff in gaps:
        disk_val = be16(vd, doff)
        print(f"  0x{gaddr:04x} → disk 0x{doff:02x} = 0x{disk_val:04x} ({disk_val:5d})  {'✓ zero' if disk_val == 0 else '⚠ non-zero'}")


if __name__ == "__main__":
    main()

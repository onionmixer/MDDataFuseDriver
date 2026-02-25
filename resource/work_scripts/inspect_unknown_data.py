#!/usr/bin/env python3
"""LBA 2112–3787 미확인 데이터 영역 분석"""
import struct
import hashlib

IMG = "/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/work/mddata_mgmt.bin"
SECTOR = 2048

def hexdump(data, offset=0, limit=256):
    """hex dump 출력"""
    lines = []
    for row in range(0, min(len(data), limit), 16):
        hex_part = " ".join(f"{data[row+i]:02x}" for i in range(min(16, len(data) - row)))
        ascii_part = "".join(
            chr(data[row+i]) if 32 <= data[row+i] < 127 else "."
            for i in range(min(16, len(data) - row))
        )
        lines.append(f"  {offset+row:08x}: {hex_part:<48s}  {ascii_part}")
    return "\n".join(lines)


def find_signatures(data, lba_start):
    """알려진 파일 시그니처 검색"""
    sigs = [
        (b"MZ",           "DOS/PE executable"),
        (b"PK\x03\x04",   "ZIP archive"),
        (b"\x89PNG",       "PNG image"),
        (b"\xff\xd8\xff",  "JPEG image"),
        (b"GIF8",          "GIF image"),
        (b"RIFF",          "RIFF (AVI/WAV)"),
        (b"%PDF",          "PDF document"),
        (b"Exif",          "Exif data"),
        (b"\x7fELF",       "ELF binary"),
        (b"BM",            "BMP image"),
        (b"\x00\x00\x01\x00", "ICO file"),
        (b"II\x2a\x00",   "TIFF (LE)"),
        (b"MM\x00\x2a",   "TIFF (BE)"),
        (b"NE",            "NE executable"),
        (b"LE",            "LE executable"),
        (b"\xca\xfe\xba\xbe", "Java class / Mach-O fat"),
        (b"SQLite",        "SQLite database"),
    ]

    results = []
    for i in range(0, len(data) - 4, SECTOR):
        sector_data = data[i:i+16]
        lba = lba_start + i // SECTOR
        for sig, desc in sigs:
            if sector_data[:len(sig)] == sig:
                results.append((lba, i, desc))

    # 섹터 내부에서도 JPEG/Exif 마커 검색 (섹터 경계가 아닐 수 있음)
    for offset in range(0, len(data) - 4):
        if data[offset:offset+3] == b"\xff\xd8\xff" and offset % SECTOR != 0:
            lba = lba_start + offset // SECTOR
            intra = offset % SECTOR
            results.append((lba, offset, f"JPEG marker (intra-sector +0x{intra:x})"))
        if data[offset:offset+4] == b"Exif" and offset % SECTOR != 0:
            lba = lba_start + offset // SECTOR
            intra = offset % SECTOR
            results.append((lba, offset, f"Exif marker (intra-sector +0x{intra:x})"))

    return results


def analyze_range(img_data, lba_start, lba_end, label):
    """LBA 범위의 데이터 분석"""
    offset_start = lba_start * SECTOR
    offset_end = (lba_end + 1) * SECTOR
    data = img_data[offset_start:offset_end]
    sector_count = lba_end - lba_start + 1

    print(f"=== {label}: LBA {lba_start}–{lba_end} ({sector_count} sectors, {len(data)} bytes) ===")
    print()

    # 첫 256바이트
    print(f"--- 시작 (LBA {lba_start}) ---")
    print(hexdump(data, offset_start, 256))
    print()

    # 마지막 256바이트
    if len(data) > 512:
        tail_start = max(0, len(data) - 256)
        tail_lba = lba_start + tail_start // SECTOR
        print(f"--- 끝 (LBA {lba_end} 부근) ---")
        print(hexdump(data[tail_start:], offset_start + tail_start, 256))
        print()

    # 시그니처 검색
    sigs = find_signatures(data, lba_start)
    if sigs:
        print(f"--- 파일 시그니처 발견 ---")
        for lba, off, desc in sigs[:20]:  # 최대 20개
            print(f"  LBA {lba} (offset 0x{offset_start + off:08x}): {desc}")
        if len(sigs) > 20:
            print(f"  ... 외 {len(sigs) - 20}개")
        print()

    # 문자열 검색 (8+ 연속 printable ASCII)
    strings = []
    current = []
    current_start = 0
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not current:
                current_start = i
            current.append(chr(b))
        else:
            if len(current) >= 8:
                s = "".join(current)
                strings.append((current_start, s))
            current = []
    if len(current) >= 8:
        strings.append((current_start, "".join(current)))

    if strings:
        print(f"--- 주요 문자열 ({len(strings)}개, 8+ chars) ---")
        shown = set()
        for off, s in strings:
            # 중복 제거, 최대 30개
            short = s[:80]
            if short not in shown and len(shown) < 30:
                lba = lba_start + off // SECTOR
                print(f"  LBA {lba} +0x{off % SECTOR:03x}: {short!r}")
                shown.add(short)
        print()

    # 엔트로피 추정 (바이트 분포)
    from collections import Counter
    freq = Counter(data)
    total = len(data)
    import math
    entropy = -sum((c/total) * math.log2(c/total) for c in freq.values() if c > 0)
    print(f"--- 통계 ---")
    print(f"  바이트 엔트로피: {entropy:.2f} bits (max 8.0)")
    print(f"  0x00 바이트: {freq.get(0, 0)} ({freq.get(0, 0)/total*100:.1f}%)")
    print(f"  0xFF 바이트: {freq.get(0xFF, 0)} ({freq.get(0xFF, 0)/total*100:.1f}%)")

    # 고빈도 바이트
    top5 = freq.most_common(5)
    print(f"  상위 5 바이트: {', '.join(f'0x{b:02x}({c})' for b, c in top5)}")
    print()

    return data


def main():
    with open(IMG, "rb") as f:
        img_data = f.read()

    print(f"이미지: {IMG} ({len(img_data)} bytes)")
    print()

    # Z920.EXE 끝 확인
    z920_end_lba = 1568 + (1110476 + SECTOR - 1) // SECTOR - 1
    z920_last_au = 392 + (1110476 + 8192 - 1) // 8192 - 1  # last AU
    print(f"Z920.EXE: LBA 1568–{z920_end_lba} (AU 392–{z920_last_au})")
    print(f"Z920.EXE 마지막 AU 끝: LBA {(z920_last_au + 1) * 4 - 1}")
    print()

    # LBA 2111 (Z920.EXE와 다음 데이터 사이의 갭)
    gap1_data = img_data[2111 * SECTOR:2112 * SECTOR]
    if all(b == 0 for b in gap1_data):
        print(f"LBA 2111: 전부 0x00 (Z920.EXE 마지막 AU 패딩)")
    else:
        print(f"LBA 2111: 비어있지 않음")
        print(hexdump(gap1_data, 2111 * SECTOR, 64))
    print()

    # 영역 1: LBA 2112–3702
    data1 = analyze_range(img_data, 2112, 3702, "영역 A")

    # LBA 3703 갭
    gap2_data = img_data[3703 * SECTOR:3704 * SECTOR]
    if all(b == 0 for b in gap2_data):
        print(f"LBA 3703: 전부 0x00 (갭)")
    else:
        print(f"LBA 3703: 비어있지 않음")
    print()

    # 영역 2: LBA 3704–3787
    data2 = analyze_range(img_data, 3704, 3787, "영역 B")

    # 영역 A를 파일로 저장
    with open("/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/work/unknown_region_a.bin", "wb") as f:
        f.write(data1)
    with open("/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/work/unknown_region_b.bin", "wb") as f:
        f.write(data2)

    print("--- 파일 저장 ---")
    print(f"  영역 A → work/unknown_region_a.bin ({len(data1)} bytes)")
    print(f"  영역 B → work/unknown_region_b.bin ({len(data2)} bytes)")


if __name__ == "__main__":
    main()

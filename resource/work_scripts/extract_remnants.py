#!/usr/bin/env python3
"""이전 파일 잔해물 추출 및 분석"""
import struct

IMG = "/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/work/mddata_mgmt.bin"
SECTOR = 2048
ALLOC_SIZE = 4  # sectors per AU

with open(IMG, "rb") as f:
    img = f.read()


# === 영역 B: JPEG 추출 ===
print("=== 영역 B: JPEG 이미지 ===")
jpeg_start = 3704 * SECTOR
jpeg_data = img[jpeg_start:]

# JPEG 끝 마커 (FF D9) 검색
jpeg_end = -1
for i in range(len(jpeg_data) - 1):
    if jpeg_data[i] == 0xFF and jpeg_data[i+1] == 0xD9:
        jpeg_end = i + 2
        # 마지막 FF D9를 찾기 (progressive JPEG 등에서 여러 개 있을 수 있음)

# 마지막 FF D9 검색
last_ffd9 = -1
for i in range(len(jpeg_data) - 2, -1, -1):
    if jpeg_data[i] == 0xFF and jpeg_data[i+1] == 0xD9:
        last_ffd9 = i + 2
        break

if last_ffd9 > 0:
    jpeg_actual = jpeg_data[:last_ffd9]
    out_path = "/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/work/remnant_image.jpg"
    with open(out_path, "wb") as f:
        f.write(jpeg_actual)

    end_lba = 3704 + last_ffd9 // SECTOR
    end_au = (3704 + last_ffd9 // SECTOR) // ALLOC_SIZE
    print(f"  JPEG 크기: {last_ffd9} bytes ({last_ffd9 / 1024:.1f} KB)")
    print(f"  범위: LBA 3704 ~ LBA {end_lba} (offset +0x{last_ffd9:x})")
    print(f"  → 추출: {out_path}")

    # Exif 정보 추출
    # TIFF 헤더 위치 찾기
    exif_offset = jpeg_data.find(b"Exif\x00\x00")
    if exif_offset >= 0:
        tiff_start = exif_offset + 6
        byte_order = jpeg_data[tiff_start:tiff_start+2]
        print(f"  Exif byte order: {'Big-endian (Motorola)' if byte_order == b'MM' else 'Little-endian (Intel)'}")

        # Exif IFD0에서 기본 정보 추출
        # APP1 marker 직후의 Exif 헤더에서 이미지 크기 읽기
        # SOF0 마커 (FF C0) 에서 실제 이미지 크기 읽기
        for i in range(len(jpeg_actual) - 8):
            if jpeg_actual[i] == 0xFF and jpeg_actual[i+1] in (0xC0, 0xC2):
                # SOF marker: length(2), precision(1), height(2), width(2)
                height = struct.unpack_from(">H", jpeg_actual, i + 5)[0]
                width = struct.unpack_from(">H", jpeg_actual, i + 7)[0]
                sof_type = "SOF0 (Baseline)" if jpeg_actual[i+1] == 0xC0 else "SOF2 (Progressive)"
                print(f"  {sof_type}: {width} × {height} pixels")
                break

    # plasq skitch 정보
    skitch_offset = jpeg_data.find(b"plasq skitch")
    if skitch_offset >= 0:
        print(f"  소프트웨어: plasq skitch (macOS 스크린샷/주석 도구)")

    icc_offset = jpeg_data.find(b"Copyright Apple")
    if icc_offset >= 0:
        icc_str = jpeg_data[icc_offset:icc_offset+40].split(b"\x00")[0].decode("ascii", errors="replace")
        print(f"  ICC 프로파일: {icc_str}")
else:
    print("  ⚠ JPEG 끝 마커 (FF D9) 없음")

print()

# === 영역 A: 압축 데이터 분석 ===
print("=== 영역 A: LBA 2112–3702 ===")
region_a_start = 2112 * SECTOR
region_a_end = 3703 * SECTOR
region_a = img[region_a_start:region_a_end]

# 비어있지 않은 마지막 섹터 찾기
last_nonzero_lba = 2112
for lba in range(3702, 2111, -1):
    sector_off = lba * SECTOR
    sector = img[sector_off:sector_off + SECTOR]
    if any(b != 0 for b in sector):
        last_nonzero_lba = lba
        break

last_nonzero_au = last_nonzero_lba // ALLOC_SIZE
actual_data_sectors = last_nonzero_lba - 2112 + 1
actual_data_bytes = actual_data_sectors * SECTOR

print(f"  비어있지 않은 마지막 LBA: {last_nonzero_lba} (AU {last_nonzero_au})")
print(f"  실제 데이터: LBA 2112–{last_nonzero_lba} ({actual_data_sectors} sectors, {actual_data_bytes} bytes)")
print(f"  빈 후행 영역: LBA {last_nonzero_lba + 1}–3702 ({3702 - last_nonzero_lba} sectors)")
print()

# AU 경계에서 패턴 확인
print("  AU 경계 첫 16바이트:")
for au_offset in range(0, min(actual_data_sectors, 40), ALLOC_SIZE):
    lba = 2112 + au_offset
    off = lba * SECTOR
    first16 = " ".join(f"{img[off+i]:02x}" for i in range(16))
    print(f"    LBA {lba:4d} (AU {lba // ALLOC_SIZE:3d}): {first16}")

print()

# 비트맵 대조: 이 영역의 AU가 할당 비트맵에서 어떻게 표시되는지 확인
print("=== VSB 비트맵 대조 ===")
vsb_offset = 1057 * SECTOR
vsb = img[vsb_offset:vsb_offset + SECTOR]

# Z920.EXE AU 범위
z920_start_au = 392
z920_end_au = 392 + (1110476 + 8191) // 8192 - 1
print(f"Z920.EXE AU 범위: {z920_start_au}–{z920_end_au} (136 AU)")

# 영역 A AU 범위
region_a_start_au = 2112 // ALLOC_SIZE  # AU 528
region_a_end_au = last_nonzero_lba // ALLOC_SIZE
print(f"영역 A AU 범위: {region_a_start_au}–{region_a_end_au}")

# 영역 B AU 범위
region_b_start_au = 3704 // ALLOC_SIZE  # AU 926
print(f"영역 B AU 범위: {region_b_start_au}–{3787 // ALLOC_SIZE}")
print()

# 비트맵에서 해당 AU들의 할당 상태 확인
print("비트맵 할당 상태:")
for label, au_s, au_e in [
    ("Z920.EXE", z920_start_au, z920_end_au),
    ("영역 A", region_a_start_au, region_a_end_au),
    ("영역 B", region_b_start_au, 3787 // ALLOC_SIZE),
]:
    allocated = 0
    free = 0
    for au in range(au_s, au_e + 1):
        byte_idx = au // 8
        bit_idx = au % 8
        if byte_idx < len(vsb):
            # MSB-first 가정
            bit_msb = (vsb[byte_idx] >> (7 - bit_idx)) & 1
            # LSB-first 가정
            bit_lsb = (vsb[byte_idx] >> bit_idx) & 1
            # 0xFF 영역은 둘 다 1이므로 구분 불가
            # 0x55 영역: MSB-first → 0,1,0,1,0,1,0,1 (odd bits), LSB-first → 1,0,1,0,1,0,1,0 (even bits)
            allocated += bit_lsb  # 여기서는 LSB-first로 시도
            free += (1 - bit_lsb)
    print(f"  {label} (AU {au_s}–{au_e}): LSB-first 기준 allocated={allocated}, free={free}")

print()

# 0x55 비트맵 영역의 실제 데이터 존재 여부 대조
print("=== 0x55 비트맵 영역 AU 샘플링 (AU 512–543) ===")
print("  AU 번호: 비트맵 값 (LSB)  →  LBA  →  데이터 존재?")
for au in range(512, 544):
    byte_idx = au // 8  # = 64, 65, 66, 67
    bit_idx = au % 8
    bit_lsb = (vsb[byte_idx] >> bit_idx) & 1
    bit_msb = (vsb[byte_idx] >> (7 - bit_idx)) & 1
    lba = au * ALLOC_SIZE
    if lba * SECTOR < len(img):
        sector = img[lba * SECTOR:(lba + 1) * SECTOR]
        has_data = any(b != 0 for b in sector[:64])
    else:
        has_data = "?"
    print(f"  AU {au:4d}: byte[{byte_idx}]=0x{vsb[byte_idx]:02x}"
          f"  LSB-bit{bit_idx}={bit_lsb}  MSB-bit{7-bit_idx}={bit_msb}"
          f"  → LBA {lba:5d}  data={'YES' if has_data else 'no'}")

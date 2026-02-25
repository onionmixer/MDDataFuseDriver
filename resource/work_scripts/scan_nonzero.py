#!/usr/bin/env python3
"""읽은 MD DATA 이미지에서 비어있지 않은 섹터를 찾는 스크립트"""
import sys

SECTOR_SIZE = 2048

def scan(path):
    with open(path, "rb") as f:
        data = f.read()

    total = len(data) // SECTOR_SIZE
    print(f"파일 크기: {len(data)} bytes, 섹터 수: {total}")
    print()

    nonzero_sectors = []
    for i in range(total):
        sector = data[i * SECTOR_SIZE : (i + 1) * SECTOR_SIZE]
        if any(b != 0 for b in sector):
            nonzero_sectors.append(i)

    print(f"비어있지 않은 섹터: {len(nonzero_sectors)}개 / {total}개")
    print()

    if not nonzero_sectors:
        print("모든 섹터가 비어있습니다!")
        return

    # 연속 범위로 그룹핑
    ranges = []
    start = nonzero_sectors[0]
    end = start
    for s in nonzero_sectors[1:]:
        if s == end + 1:
            end = s
        else:
            ranges.append((start, end))
            start = s
            end = s
    ranges.append((start, end))

    print("비어있지 않은 영역:")
    for start, end in ranges:
        count = end - start + 1
        offset = start * SECTOR_SIZE
        print(f"  LBA {start}-{end} ({count}섹터, offset 0x{offset:08X}-0x{(end+1)*SECTOR_SIZE-1:08X})")

    # 첫 비어있지 않은 섹터의 처음 128바이트 표시
    print()
    for start, end in ranges[:5]:  # 처음 5개 영역만
        sector = data[start * SECTOR_SIZE : start * SECTOR_SIZE + 128]
        print(f"LBA {start} 처음 128바이트:")
        for row in range(8):
            off = row * 16
            hex_part = " ".join(f"{b:02x}" for b in sector[off:off+16])
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in sector[off:off+16])
            print(f"  {off:04x}: {hex_part}  {ascii_part}")
        print()

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/work/mddata_mgmt.bin"
    scan(path)

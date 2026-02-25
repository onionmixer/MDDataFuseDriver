#!/usr/bin/env python3
"""지정한 LBA 섹터들의 내용을 hex dump"""
import sys

IMG = "/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/work/mddata_mgmt.bin"
SECTOR = 2048
DUMP_BYTES = 512  # 각 섹터에서 표시할 바이트 수 (비어있지 않은 부분까지)

targets = [1057, 1059, 1060, 1061]

with open(IMG, "rb") as f:
    for lba in targets:
        f.seek(lba * SECTOR)
        data = f.read(SECTOR)

        # 마지막 비어있지 않은 바이트 위치
        last_nz = 0
        for i in range(len(data)):
            if data[i] != 0:
                last_nz = i
        show = min(SECTOR, ((last_nz // 16) + 2) * 16)

        print(f"=== LBA {lba} (offset 0x{lba * SECTOR:08X}) ===")
        print(f"    비어있지 않은 마지막 바이트: 0x{last_nz:04x}")
        print()
        for row in range(0, show, 16):
            hex_part = " ".join(f"{data[row + i]:02x}" for i in range(16))
            ascii_part = "".join(
                chr(data[row + i]) if 32 <= data[row + i] < 127 else "."
                for i in range(16)
            )
            print(f"  {row:04x}: {hex_part}  {ascii_part}")
        print()

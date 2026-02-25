#!/usr/bin/env python3
"""
MDFS Volume Descriptor (VD) 파서
LBA 1056 에서 발견된 VD 구조를 분석

참조: WS19 mdfsck VD emit map (필드 순서 / 타입)
참조: WS37 endian normalization (빅엔디안 온디스크 포맷)
"""
import struct
import sys

SECTOR_SIZE = 2048
VD_LBA = 1056


def read_be16(data, off):
    return struct.unpack_from(">H", data, off)[0]


def read_be32(data, off):
    return struct.unpack_from(">I", data, off)[0]


def parse_vd(data):
    """VD 섹터 전체를 덤프하고 알려진 필드를 파싱"""

    print("=== MDFS Volume Descriptor Raw Dump ===")
    print(f"섹터 크기: {len(data)} bytes")
    print()

    # 전체 hex dump (비어있지 않은 부분까지)
    last_nonzero = 0
    for i in range(len(data)):
        if data[i] != 0:
            last_nonzero = i
    dump_end = min(len(data), ((last_nonzero // 16) + 2) * 16)

    print("Hex dump:")
    for row in range(0, dump_end, 16):
        hex_part = " ".join(f"{data[row+i]:02x}" for i in range(16) if row + i < len(data))
        ascii_part = "".join(
            chr(data[row+i]) if 32 <= data[row+i] < 127 else "."
            for i in range(16) if row + i < len(data)
        )
        print(f"  {row:04x}: {hex_part:<48s}  {ascii_part}")
    print()

    # 확인된 필드 파싱
    print("=== 파싱 결과 (빅엔디안 가정) ===")
    print()

    # Identifier
    ident = data[1:6]
    print(f"[0x01] Identifier: {ident.decode('ascii', errors='replace')!r}")
    print(f"[0x06] Version: {data[6]}")
    print()

    # 기본 디스크 파라미터
    block_size = read_be16(data, 0x10)
    cluster_size = read_be16(data, 0x12)
    alloc_size = read_be16(data, 0x14)
    print(f"[0x10] BlockSize: {block_size} bytes")
    print(f"[0x12] ClusterSize: {cluster_size} sectors")
    print(f"[0x14] AllocSize: {alloc_size} sectors")
    print(f"        → 1 cluster = {cluster_size * block_size} bytes")
    print(f"        → 1 alloc unit = {alloc_size * block_size} bytes")
    print()

    # 할당 카운터 (32-bit BE)
    num_alloc = read_be32(data, 0x18)
    num_recordable = read_be32(data, 0x1C)
    num_available = read_be32(data, 0x20)
    num_used = read_be32(data, 0x24)
    print(f"[0x18] NumAlloc: {num_alloc} AU ({num_alloc * alloc_size} sectors, {num_alloc * alloc_size * block_size / 1048576:.1f} MiB)")
    print(f"[0x1C] NumRecordable: {num_recordable} AU")
    print(f"[0x20] NumAvailable: {num_available} AU")
    print(f"[0x24] NumUsed: {num_used} AU ({num_used * alloc_size} sectors)")
    print(f"        → Used + Available = {num_used + num_available} (AllReserved = {num_alloc - num_used - num_available})")
    print()

    # 0x28 이후: 남은 필드들 탐색적 파싱
    # WS19 필드 순서: NumDefective, NumDir, NumFile, MaxIdNum, VolAttr,
    #                  VMALen, VMALoc, VSBLoc, VSBNum, MTBLoc, MTBNum,
    #                  ERBLoc, ERBNum, DRBLoc, DRBNum, DirLen, NumChild
    print("=== 0x28 이후 탐색적 파싱 ===")
    print()

    # 여러 해석 시도: 16-bit BE, 32-bit BE
    print("16-bit BE 워드 시퀀스:")
    for off in range(0x28, min(0x80, len(data)), 2):
        val = read_be16(data, off)
        if val != 0:
            print(f"  [0x{off:02x}] = 0x{val:04x} ({val})")

    print()
    print("32-bit BE 더블워드 시퀀스:")
    for off in range(0x28, min(0x80, len(data)), 4):
        val = read_be32(data, off)
        if val != 0:
            print(f"  [0x{off:02x}] = 0x{val:08x} ({val})")

    print()

    # VD 두 번째 섹터도 확인 (LBA 1057)
    return {
        "block_size": block_size,
        "cluster_size": cluster_size,
        "alloc_size": alloc_size,
        "num_alloc": num_alloc,
        "num_used": num_used,
        "vd_lba": VD_LBA,
    }


def main():
    img_path = sys.argv[1] if len(sys.argv) > 1 else "/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/work/mddata_mgmt.bin"

    with open(img_path, "rb") as f:
        f.seek(VD_LBA * SECTOR_SIZE)
        vd_sector0 = f.read(SECTOR_SIZE)
        vd_sector1 = f.read(SECTOR_SIZE)

    print(f"이미지: {img_path}")
    print(f"VD 위치: LBA {VD_LBA} (offset 0x{VD_LBA * SECTOR_SIZE:08X})")
    print()

    info = parse_vd(vd_sector0)

    # VD 두 번째 섹터
    if any(b != 0 for b in vd_sector1):
        print("=== VD 두 번째 섹터 (LBA 1057) ===")
        last_nz = max(i for i in range(len(vd_sector1)) if vd_sector1[i] != 0)
        dump_end = min(len(vd_sector1), ((last_nz // 16) + 2) * 16)
        for row in range(0, dump_end, 16):
            hex_part = " ".join(f"{vd_sector1[row+i]:02x}" for i in range(16))
            ascii_part = "".join(
                chr(vd_sector1[row+i]) if 32 <= vd_sector1[row+i] < 127 else "."
                for i in range(16)
            )
            print(f"  {row:04x}: {hex_part}  {ascii_part}")


if __name__ == "__main__":
    main()

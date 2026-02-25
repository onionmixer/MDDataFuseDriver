#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path


def read_u16(b: bytes, off: int) -> int:
    return int.from_bytes(b[off : off + 2], "little")


def read_u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off : off + 4], "little")


def main() -> int:
    ap = argparse.ArgumentParser(description="Patch AUTOEXEC.BAT in a FAT12 floppy image")
    ap.add_argument("--image", required=True, help="FAT12 image path")
    ap.add_argument("--out", required=True, help="output image path")
    ap.add_argument("--script", required=True, help="text file to write as AUTOEXEC.BAT")
    args = ap.parse_args()

    src = Path(args.image)
    out = Path(args.out)
    script = Path(args.script)

    img = bytearray(src.read_bytes())
    payload = script.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")

    bps = read_u16(img, 11)
    spc = img[13]
    reserved = read_u16(img, 14)
    fats = img[16]
    root_entries = read_u16(img, 17)
    sectors_per_fat = read_u16(img, 22)

    root_dir_sectors = (root_entries * 32 + (bps - 1)) // bps
    fat_area_sectors = fats * sectors_per_fat
    first_root_sector = reserved + fat_area_sectors
    first_data_sector = first_root_sector + root_dir_sectors

    root_off = first_root_sector * bps
    root_size = root_entries * 32
    root = img[root_off : root_off + root_size]

    entry_off = -1
    for i in range(0, len(root), 32):
        name = root[i : i + 11]
        if name == b"AUTOEXECBAT":
            entry_off = i
            break
    if entry_off < 0:
        raise SystemExit("AUTOEXEC.BAT entry not found")

    cluster = read_u16(root, entry_off + 26)
    if cluster < 2:
        raise SystemExit(f"invalid start cluster: {cluster}")

    cluster_size = bps * spc
    if len(payload) > cluster_size:
        raise SystemExit(
            f"script too large for single cluster: {len(payload)} > {cluster_size}"
        )

    first_sector_of_cluster = first_data_sector + (cluster - 2) * spc
    data_off = first_sector_of_cluster * bps
    img[data_off : data_off + cluster_size] = b"\x00" * cluster_size
    img[data_off : data_off + len(payload)] = payload

    file_size_off = root_off + entry_off + 28
    img[file_size_off : file_size_off + 4] = len(payload).to_bytes(4, "little")

    out.write_bytes(img)
    print(
        f"patched AUTOEXEC.BAT cluster={cluster} old_size={read_u32(root, entry_off+28)} "
        f"new_size={len(payload)} out={out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""MDFS 이미지에서 DRB 엔트리 기반으로 파일 추출"""
import struct
import sys
import hashlib

IMG = "/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/work/mddata_mgmt.bin"
SECTOR = 2048
ALLOC_SIZE = 4  # sectors per AU


def be16(data, off):
    return struct.unpack_from(">H", data, off)[0]


def be32(data, off):
    return struct.unpack_from(">I", data, off)[0]


def parse_drb_entry(data, offset):
    """42바이트 DRB 엔트리 파싱"""
    raw = data[offset:offset + 42]
    if len(raw) < 42:
        return None

    name_raw = raw[0x06:0x10]  # 10 bytes: 7+3
    name_part = name_raw[:7].rstrip(b" ").decode("ascii", errors="replace")
    ext_part = name_raw[7:10].rstrip(b" ").decode("ascii", errors="replace")

    filename = f"{name_part}.{ext_part}" if ext_part else name_part

    return {
        "id": be16(raw, 0x00),
        "type": be16(raw, 0x02),
        "attr": be16(raw, 0x04),
        "filename": filename,
        "name_raw": name_raw,
        "ctime": be32(raw, 0x10),
        "mtime": be32(raw, 0x14),
        "atime": be32(raw, 0x18),
        "children": be32(raw, 0x1C),
        "size": be32(raw, 0x20),
        "unknown_24": be16(raw, 0x24),
        "start_au": be16(raw, 0x26),
        "unknown_28": be16(raw, 0x28),
    }


def main():
    with open(IMG, "rb") as f:
        img_data = f.read()

    img_sectors = len(img_data) // SECTOR
    print(f"이미지: {IMG}")
    print(f"이미지 크기: {len(img_data)} bytes ({img_sectors} sectors)")
    print()

    # VD에서 DRB 위치 읽기
    vd_offset = 1056 * SECTOR
    vma_loc = be32(img_data, vd_offset + 0x40)
    drb_loc = be16(img_data, vd_offset + 0x50)
    drb_num = be16(img_data, vd_offset + 0x52)
    drb_lba = vma_loc + drb_loc

    print(f"VMALoc: {vma_loc}, DRBLoc: +{drb_loc} = LBA {drb_lba}")
    print(f"DRBNum: {drb_num} sectors")
    print()

    # DRB 엔트리 스캔
    drb_offset = drb_lba * SECTOR
    drb_data = img_data[drb_offset:drb_offset + drb_num * SECTOR]

    entries = []
    for i in range(drb_num * SECTOR // 42):
        entry = parse_drb_entry(drb_data, i * 42)
        if entry is None:
            break
        # 빈 엔트리 감지 (모두 0)
        if entry["id"] == 0 and entry["type"] == 0 and entry["size"] == 0 and entry["start_au"] == 0:
            break
        entries.append(entry)

    print(f"DRB 엔트리 수: {len(entries)}")
    print()

    for i, e in enumerate(entries):
        is_dir = (e["name_raw"] == b"          ")  # 공백 10자 = 루트
        label = "(root)" if is_dir else e["filename"]
        start_lba = e["start_au"] * ALLOC_SIZE

        print(f"  [{i}] {label}")
        print(f"      ID=0x{e['id']:04x} Type=0x{e['type']:04x} Attr=0x{e['attr']:04x}")
        print(f"      Size={e['size']} bytes, StartAU={e['start_au']} (LBA {start_lba})")
        print(f"      Children={e['children']}")

        if not is_dir and e["size"] > 0:
            # 파일 추출
            file_offset = start_lba * SECTOR
            file_size = e["size"]
            file_end = file_offset + file_size

            if file_end > len(img_data):
                print(f"      ⚠ 이미지 범위 초과! (필요: LBA {start_lba}–{start_lba + (file_size + SECTOR - 1) // SECTOR - 1}, 이미지: 0–{img_sectors - 1})")
                continue

            file_data = img_data[file_offset:file_offset + file_size]

            # 해시
            sha1 = hashlib.sha1(file_data).hexdigest()
            md5 = hashlib.md5(file_data).hexdigest()

            # MZ header 확인
            magic = file_data[:2] if len(file_data) >= 2 else b""
            magic_str = magic.decode("ascii", errors="replace")

            out_path = f"/mnt/USERS/onion/DATA_ORIGN/Workspace/MDH10/work/{e['filename']}"
            with open(out_path, "wb") as out:
                out.write(file_data)

            print(f"      Magic: {magic_str!r} ({magic.hex()})")
            print(f"      SHA-1: {sha1}")
            print(f"      MD5:   {md5}")
            print(f"      → 추출 완료: {out_path}")

        print()


if __name__ == "__main__":
    main()

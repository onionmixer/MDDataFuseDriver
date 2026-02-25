#!/usr/bin/env python3
"""
Adaptec USBXchange .fw (binary INTEL_HEX_RECORD) → Intel HEX 텍스트 변환기

.fw 구조 (28바이트/레코드, LE):
  u32 length   (데이터 길이, 최대 16)
  u32 address  (타겟 주소)
  u32 type     (0=데이터, 비0=종료)
  u8  data[16]
"""
import struct
import sys

RECORD_SIZE = 28  # 4+4+4+16
RECORD_FMT = "<III16s"  # length, address, type, data[16]


def ihex_line(rec_type, address, data):
    """표준 Intel HEX 라인 생성 (:LLAAAATT[DD...]CC)"""
    length = len(data)
    raw = [length, (address >> 8) & 0xFF, address & 0xFF, rec_type] + list(data)
    checksum = (-sum(raw)) & 0xFF
    hex_str = "".join(f"{b:02X}" for b in raw) + f"{checksum:02X}"
    return ":" + hex_str


def convert(fw_path, ihex_path):
    with open(fw_path, "rb") as f:
        fw_data = f.read()

    if len(fw_data) % RECORD_SIZE != 0:
        print(f"경고: 파일 크기 {len(fw_data)}가 레코드 크기 {RECORD_SIZE}의 배수가 아님",
              file=sys.stderr)

    num_records = len(fw_data) // RECORD_SIZE
    lines = []
    data_count = 0

    for i in range(num_records):
        offset = i * RECORD_SIZE
        length, address, rec_type, raw_data = struct.unpack_from(
            RECORD_FMT, fw_data, offset
        )

        if rec_type != 0:
            # 종료 레코드
            break

        data = raw_data[:length]
        data_count += 1

        # 주소가 16비트를 초과하면 Extended Linear Address 레코드 필요
        if address > 0xFFFF:
            ext_addr = (address >> 16) & 0xFFFF
            lines.append(ihex_line(0x04, 0x0000,
                                   [(ext_addr >> 8) & 0xFF, ext_addr & 0xFF]))
            address = address & 0xFFFF

        lines.append(ihex_line(0x00, address, data))

    # EOF 레코드
    lines.append(ihex_line(0x01, 0x0000, []))

    with open(ihex_path, "w") as f:
        for line in lines:
            f.write(line + "\n")

    print(f"변환 완료: {data_count}개 데이터 레코드 → {ihex_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"사용법: {sys.argv[0]} input.fw [output.ihex]")
        sys.exit(1)

    fw_path = sys.argv[1]
    ihex_path = sys.argv[2] if len(sys.argv) > 2 else fw_path.replace(".fw", ".ihex")
    convert(fw_path, ihex_path)

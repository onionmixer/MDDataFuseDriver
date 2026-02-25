#!/usr/bin/env python3
from __future__ import annotations

import struct
from pathlib import Path


TARGETS = [0x0209, 0x020A, 0x0202, 0x0243, 0x0242]
FILES = [
    Path("w31/extract/mdcache.exe"),
    Path("w31/extract/mdformat.exe"),
    Path("w31/extract/mdfsck.exe"),
    Path("w31/extract/mdfsex.exe"),
]


def mz_header_size(data: bytes) -> int:
    if data[:2] != b"MZ":
        raise ValueError("not MZ")
    return struct.unpack_from("<H", data, 0x08)[0] * 16


def scan_patterns(buf: bytes, base: int, v: int) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    lo = v.to_bytes(2, "little")
    n = len(buf)
    for i in range(0, n - 3):
        b0 = buf[i]
        # cmp ax, imm16
        if b0 == 0x3D and buf[i + 1 : i + 3] == lo:
            out.append((base + i, "cmp ax, imm16"))
        # push imm16
        if b0 == 0x68 and buf[i + 1 : i + 3] == lo:
            out.append((base + i, "push imm16"))
        # mov r16, imm16 (B8..BF)
        if 0xB8 <= b0 <= 0xBF and buf[i + 1 : i + 3] == lo:
            out.append((base + i, f"mov r16, imm16 (reg={b0-0xB8})"))
        # cmp r/m16, imm16 (81 /7)
        if i + 4 < n and b0 == 0x81:
            modrm = buf[i + 1]
            reg = (modrm >> 3) & 0x07
            if reg == 7 and buf[i + 2 : i + 4] == lo:
                out.append((base + i, "cmp r/m16, imm16"))
    return out


def scan_raw_hits(buf: bytes, base: int, v: int) -> list[int]:
    lo = v.to_bytes(2, "little")
    out: list[int] = []
    start = 0
    while True:
        p = buf.find(lo, start)
        if p < 0:
            break
        out.append(base + p)
        start = p + 1
    return out


def main() -> None:
    md_lines: list[str] = [
        "# imm16 Usage Scan (WS8)",
        "",
        "Date: 2026-02-17",
        "",
        "Targets: `0x0209`, `0x020A`, `0x0202`, `0x0243`, `0x0242`",
        "",
    ]
    csv_lines = ["file,target,kind,offset_hex"]

    for p in FILES:
        data = p.read_bytes()
        hdr = mz_header_size(data)
        code = data[hdr:]
        md_lines.append(f"## {p.as_posix()}")
        md_lines.append(f"- header_size: `0x{hdr:04x}`")
        any_hit = False

        for v in TARGETS:
            typed = scan_patterns(code, hdr, v)
            raw = scan_raw_hits(code, hdr, v)
            typed_set = {o for o, _ in typed}
            raw_only = [o for o in raw if o not in typed_set]

            md_lines.append(f"- target `0x{v:04x}`:")
            md_lines.append(f"  typed_hits={len(typed)} raw_hits={len(raw)} raw_only={len(raw_only)}")
            if typed:
                any_hit = True
                for off, kind in typed:
                    md_lines.append(f"  - {kind} @ `0x{off:05x}`")
                    csv_lines.append(f"{p.as_posix()},0x{v:04x},{kind},0x{off:05x}")

        if not any_hit:
            md_lines.append("- typed opcode hits: none")
        md_lines.append("")

    Path("analysis/ws8_imm16_usage.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    Path("analysis/ws8_imm16_usage.csv").write_text("\n".join(csv_lines) + "\n", encoding="utf-8")
    print("wrote analysis/ws8_imm16_usage.md and analysis/ws8_imm16_usage.csv")


if __name__ == "__main__":
    main()

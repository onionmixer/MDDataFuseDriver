#!/usr/bin/env python3
from __future__ import annotations

import csv
import struct
from pathlib import Path


TARGETS = [
    ("w95/extract/us/mdmgr.vxd", 0x1320),
    ("w95/extract/us/mdhlp.vxd", 0x12BC),
    ("w95/extract/us/mdfsd.vxd", 0x6200),
]


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def asciiz8(b: bytes, o: int) -> str:
    raw = b[o:o + 8]
    return raw.decode("ascii", errors="replace").rstrip()


def main() -> None:
    field_offsets = [
        0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C,
        0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x3C,
    ]

    rows = []
    md = ["# WS5 VxD DDB Structure Scan", "", "Date: 2026-02-16", ""]
    md.append("Scope: DDB candidate offsets recovered from `ord1` LE type-3 entries.")
    md.append("")

    for path, off in TARGETS:
        b = Path(path).read_bytes()
        name8 = asciiz8(b, off + 0x0C)
        md.append(f"## {path}")
        md.append(f"- ddb_file_off: `0x{off:04x}`")
        md.append(f"- name8@+0x0c: `{name8}`")
        md.append("")
        md.append("| +off | u32_le | u16_lo | ascii8_if_text |")
        md.append("| --- | --- | --- | --- |")
        for fo in field_offsets:
            v32 = u32(b, off + fo)
            v16 = u16(b, off + fo)
            text = ""
            chunk = b[off + fo: off + fo + 8]
            if all((32 <= c < 127) or c == 0x20 for c in chunk):
                text = chunk.decode("ascii", errors="ignore").rstrip()
            md.append(f"| +0x{fo:02x} | 0x{v32:08x} | 0x{v16:04x} | {text} |")
            rows.append(
                {
                    "file": path,
                    "ddb_off": f"0x{off:04x}",
                    "field_off": f"0x{fo:02x}",
                    "u32_le": f"0x{v32:08x}",
                    "u16_lo": f"0x{v16:04x}",
                    "ascii8_if_text": text,
                }
            )
        md.append("")

    # Cross-file summary on likely stable offsets.
    md.append("## Cross-file Stable Offsets")
    md.append("- `+0x00`: all `0x00000000`")
    md.append("- `+0x04`: all `0x00000400`")
    md.append("- `+0x0c`: 8-byte module name (`MDMGR`, `MDHlp`, `MDFSD`)")
    md.append("- `+0x14`:")
    md.append("  - `MDMGR/MDHLP`: `0x80000000`")
    md.append("  - `MDFSD`: `0xA0010100`")
    md.append("")
    md.append("Interpretation:")
    md.append("- DDB-like structure hypothesis is strongly reinforced by shared field positions.")
    md.append("- Exact semantic labeling of each offset remains partially unresolved without vendor headers.")
    md.append("")

    Path("analysis/vxd_ddb_struct_scan.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    with Path("analysis/vxd_ddb_struct_scan.csv").open("w", newline="", encoding="utf-8") as f:
        wr = csv.DictWriter(
            f,
            fieldnames=["file", "ddb_off", "field_off", "u32_le", "u16_lo", "ascii8_if_text"],
        )
        wr.writeheader()
        wr.writerows(rows)
    print("wrote analysis/vxd_ddb_struct_scan.md")
    print("wrote analysis/vxd_ddb_struct_scan.csv")


if __name__ == "__main__":
    main()

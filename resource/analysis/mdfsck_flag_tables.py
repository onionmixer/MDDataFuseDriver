#!/usr/bin/env python3
from __future__ import annotations

import csv
import struct
from pathlib import Path


def read_c_string(data: bytes, off: int, max_len: int = 64) -> str:
    end = off
    lim = min(len(data), off + max_len)
    while end < lim and data[end] != 0:
        end += 1
    raw = data[off:end]
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return ""


def is_single_bit(v: int) -> bool:
    return v > 0 and (v & (v - 1)) == 0


def main() -> None:
    p = Path("w31/extract/mdfsck.exe")
    b = p.read_bytes()

    hdr = struct.unpack_from("<H", b, 0x08)[0] * 16
    nrel = struct.unpack_from("<H", b, 0x06)[0]
    rel_off = struct.unpack_from("<H", b, 0x18)[0]

    ptr_cells = []
    for i in range(nrel):
        off, seg = struct.unpack_from("<HH", b, rel_off + i * 4)
        loc = seg * 16 + off
        foff = hdr + loc
        if foff < 2 or foff + 1 >= len(b):
            continue
        seg_word = struct.unpack_from("<H", b, foff)[0]
        off_word = struct.unpack_from("<H", b, foff - 2)[0]
        target_lin = off_word + seg_word * 16
        target_foff = hdr + target_lin
        if target_foff < 0 or target_foff >= len(b):
            continue
        name = read_c_string(b, target_foff)
        if not name or not name.startswith("A"):
            continue
        ptr_cells.append((foff - 2, target_foff, name))

    # Group pointer entries by 4-byte stride.
    ptr_cells.sort(key=lambda x: x[0])
    groups = []
    cur = []
    for cell in ptr_cells:
        if not cur:
            cur = [cell]
            continue
        if cell[0] == cur[-1][0] + 4:
            cur.append(cell)
        else:
            if len(cur) >= 4:
                groups.append(cur)
            cur = [cell]
    if len(cur) >= 4:
        groups.append(cur)

    rows = []
    md = ["# mdfsck Attribute Flag Tables", "", "Date: 2026-02-16", ""]
    md.append(f"- relocation_count: {nrel}")
    md.append(f"- pointer_groups_detected: {len(groups)}")
    md.append("")

    for gi, g in enumerate(groups, 1):
        n = len(g)
        names_start = min(x[1] for x in g)
        ptr_start = g[0][0]

        # Find n contiguous single-bit words before names.
        flags_off = None
        flags = None
        scan_lo = max(0, names_start - 0x80)
        for off in range(scan_lo, names_start - n * 2 + 1):
            ws = [struct.unpack_from("<H", b, off + k * 2)[0] for k in range(n)]
            if all(is_single_bit(v) for v in ws):
                flags_off = off
                flags = ws
                break

        md.append(f"## table_{gi}")
        md.append(f"- pointer_table_file_off: 0x{ptr_start:05x}")
        md.append(f"- entry_count: {n}")
        md.append(f"- names_start_file_off: 0x{names_start:05x}")
        if flags_off is not None and flags is not None:
            md.append(f"- flags_array_file_off: 0x{flags_off:05x}")
        else:
            md.append("- flags_array_file_off: n/a")
        md.append("")
        md.append("| idx | flag_hex | name | ptr_file_off |")
        md.append("| --- | --- | --- | --- |")
        for i, (ptr_foff, name_foff, name) in enumerate(g):
            flag_hex = "n/a"
            if flags is not None and i < len(flags):
                flag_hex = f"0x{flags[i]:04x}"
            md.append(f"| {i+1} | {flag_hex} | {name} | 0x{name_foff:05x} |")
            rows.append(
                {
                    "table": gi,
                    "index": i + 1,
                    "flag_hex": flag_hex,
                    "name": name,
                    "name_file_off": f"0x{name_foff:05x}",
                    "pointer_entry_off": f"0x{ptr_foff:05x}",
                }
            )
        md.append("")

    Path("analysis/mdfsck_flag_tables.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    with Path("analysis/mdfsck_flag_tables.csv").open("w", newline="", encoding="utf-8") as f:
        wr = csv.DictWriter(
            f,
            fieldnames=["table", "index", "flag_hex", "name", "name_file_off", "pointer_entry_off"],
        )
        wr.writeheader()
        wr.writerows(rows)

    print("wrote analysis/mdfsck_flag_tables.md")
    print("wrote analysis/mdfsck_flag_tables.csv")


if __name__ == "__main__":
    main()

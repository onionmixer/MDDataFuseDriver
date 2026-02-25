#!/usr/bin/env python3
from __future__ import annotations

import csv
import struct
from pathlib import Path


TARGETS = [
    Path("w31/extract/mdcache.exe"),
    Path("w31/extract/mdformat.exe"),
    Path("w31/extract/mdfsck.exe"),
]


def read_cstr(data: bytes, off: int, limit: int = 96) -> str:
    if off < 0 or off >= len(data):
        return ""
    end = off
    max_end = min(len(data), off + limit)
    while end < max_end and data[end] != 0:
        end += 1
    raw = data[off:end]
    if not raw:
        return ""
    # Keep only mostly printable ASCII strings.
    if sum(32 <= c < 127 for c in raw) < max(3, int(len(raw) * 0.8)):
        return ""
    try:
        return raw.decode("ascii", errors="ignore")
    except Exception:
        return ""


def main() -> None:
    rows = []
    md = ["# Relocation-Based String Xrefs (DOS EXE)", "", "Date: 2026-02-16", ""]

    for p in TARGETS:
        b = p.read_bytes()
        hdr = struct.unpack_from("<H", b, 0x08)[0] * 16
        nrel = struct.unpack_from("<H", b, 0x06)[0]
        rel_off = struct.unpack_from("<H", b, 0x18)[0]

        local = []
        for i in range(nrel):
            roff, rseg = struct.unpack_from("<HH", b, rel_off + i * 4)
            loc = rseg * 16 + roff
            seg_fix_off = hdr + loc
            if seg_fix_off < 2 or seg_fix_off + 1 >= len(b):
                continue
            segw = struct.unpack_from("<H", b, seg_fix_off)[0]
            offw = struct.unpack_from("<H", b, seg_fix_off - 2)[0]
            target = hdr + segw * 16 + offw
            s = read_cstr(b, target)
            if not s:
                continue
            rec = {
                "file": str(p),
                "rel_index": i,
                "ptr_file_off": f"0x{seg_fix_off-2:05x}",
                "target_file_off": f"0x{target:05x}",
                "far_off": f"0x{offw:04x}",
                "far_seg": f"0x{segw:04x}",
                "text": s,
            }
            local.append(rec)
            rows.append(rec)

        md.append(f"## {p}")
        md.append(f"- relocation_count: {nrel}")
        md.append(f"- string_xref_hits: {len(local)}")
        key = [r for r in local if any(t in r["text"] for t in ["MDCTL", "MD001", "MDFS000", "MD DATA", "cache", "format"])]
        md.append(f"- key_hits: {len(key)}")
        md.append("")
        md.append("| rel# | ptr_file_off | target_file_off | text |")
        md.append("| --- | --- | --- | --- |")
        for r in key[:80]:
            txt = r["text"].replace("|", "\\|")
            md.append(f"| {r['rel_index']} | {r['ptr_file_off']} | {r['target_file_off']} | {txt} |")
        md.append("")

    Path("analysis/reloc_string_xref.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    with Path("analysis/reloc_string_xref.csv").open("w", newline="", encoding="utf-8") as f:
        wr = csv.DictWriter(
            f,
            fieldnames=["file", "rel_index", "ptr_file_off", "target_file_off", "far_off", "far_seg", "text"],
        )
        wr.writeheader()
        wr.writerows(rows)
    print("wrote analysis/reloc_string_xref.md")
    print("wrote analysis/reloc_string_xref.csv")


if __name__ == "__main__":
    main()

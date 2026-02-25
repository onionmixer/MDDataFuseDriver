#!/usr/bin/env python3
from __future__ import annotations

import csv
import struct
from pathlib import Path


TARGET_FILES = [
    Path("w31/extract/mdcache.exe"),
    Path("w31/extract/mdformat.exe"),
]

EXPECTED = [0x00000209, 0x0001020A, 0x00020202, 0x00030243, 0x00040242]


def u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def find_block(b: bytes) -> list[int]:
    hits: list[int] = []
    n = len(b)
    for off in range(0, n - (0x0E + 5 * 0x14)):
        ok = True
        for i, d0 in enumerate(EXPECTED):
            r = off + 0x0E + i * 0x14
            if u32(b, r) != d0:
                ok = False
                break
            if u32(b, r + 0x04) != 0 or u32(b, r + 0x08) != 0 or u32(b, r + 0x0C) != 0:
                ok = False
                break
            if u32(b, r + 0x10) == 0:
                ok = False
                break
        if ok:
            hits.append(off)
    return hits


def parse_block(b: bytes, base: int) -> dict:
    cbs = [u32(b, base + 0x00), u32(b, base + 0x04), u32(b, base + 0x08)]
    recs = []
    for i in range(5):
        r = base + 0x0E + i * 0x14
        d0 = u32(b, r + 0x00)
        op = d0 & 0xFFFF
        idx = (d0 >> 16) & 0xFFFF
        handler = u32(b, r + 0x10) & 0xFFFF
        recs.append({"i": i, "off": r, "d0": d0, "op": op, "idx": idx, "handler16": handler})
    return {"base": base, "callbacks": cbs, "records": recs}


def main() -> None:
    md = ["# MDCTL Descriptor Dual Extract (WS9)", "", "Date: 2026-02-17", ""]
    rows: list[dict[str, str]] = []

    for path in TARGET_FILES:
        b = path.read_bytes()
        hits = find_block(b)
        md.append(f"## {path.as_posix()}")
        md.append(f"- candidate_blocks: {len(hits)}")
        if not hits:
            md.append("- no matching block found")
            md.append("")
            continue
        if len(hits) > 1:
            md.append(f"- warning: multiple matches {', '.join(hex(h) for h in hits)}")
        blk = parse_block(b, hits[0])
        md.append(f"- selected_base: `0x{blk['base']:05x}`")
        md.append(
            "- callbacks: "
            + ", ".join(f"`0x{v:08x}`" for v in blk["callbacks"])
        )
        md.append("- records:")
        for r in blk["records"]:
            md.append(
                f"  - rec{r['i']}: off=`0x{r['off']:05x}` d0=`0x{r['d0']:08x}` "
                f"op=`0x{r['op']:04x}` idx=`{r['idx']}` handler16=`0x{r['handler16']:04x}`"
            )
            rows.append(
                {
                    "file": path.as_posix(),
                    "base": f"0x{blk['base']:05x}",
                    "record_index": str(r["i"]),
                    "record_off": f"0x{r['off']:05x}",
                    "d0": f"0x{r['d0']:08x}",
                    "op": f"0x{r['op']:04x}",
                    "idx": str(r["idx"]),
                    "handler16": f"0x{r['handler16']:04x}",
                }
            )
        md.append("")

    md.append("## Interpretation")
    md.append("- The same 5-opcode structure appears in both DOS tools.")
    md.append("- `d0` packs `(opcode_low16, index_high16)` with index sequence `0..4`.")
    md.append("- `d1..d3` are zero across all 10 records (2 binaries x 5 records).")
    md.append("- `d4` low16 is a non-zero code pointer-like value per record.")

    Path("analysis/ws9_mdctl_dual_table.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    with open("analysis/ws9_mdctl_dual_table.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=["file", "base", "record_index", "record_off", "d0", "op", "idx", "handler16"],
        )
        w.writeheader()
        w.writerows(rows)
    print("wrote analysis/ws9_mdctl_dual_table.md and .csv")


if __name__ == "__main__":
    main()

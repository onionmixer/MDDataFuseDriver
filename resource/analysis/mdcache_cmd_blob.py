#!/usr/bin/env python3
from __future__ import annotations

import struct
from pathlib import Path


def main() -> None:
    p = Path("w31/extract/mdcache.exe")
    b = p.read_bytes()
    hdr = struct.unpack_from("<H", b, 0x08)[0] * 16
    nrel = struct.unpack_from("<H", b, 0x06)[0]
    rel_off = struct.unpack_from("<H", b, 0x18)[0]

    # Known region from prior relocation hit around parser token blob.
    blob_off = 0x0D050
    blob = b[blob_off:blob_off + 0x80]

    rel_hits = []
    for i in range(nrel):
        roff, rseg = struct.unpack_from("<HH", b, rel_off + i * 4)
        loc = rseg * 16 + roff
        seg_fix = hdr + loc
        if seg_fix < 2 or seg_fix + 1 >= len(b):
            continue
        ptr_cell = seg_fix - 2
        if 0x0D000 <= ptr_cell <= 0x0D140:
            offw = struct.unpack_from("<H", b, ptr_cell)[0]
            segw = struct.unpack_from("<H", b, ptr_cell + 2)[0]
            target = hdr + segw * 16 + offw
            text = b[target:target + 64]
            asc = "".join(chr(c) if 32 <= c < 127 else "." for c in text)
            rel_hits.append((i, ptr_cell, offw, segw, target, asc))

    # Candidate descriptor dword lanes after token blob.
    d_start = 0x0D0C8
    dwords_a0 = [struct.unpack_from("<I", b, d_start + i * 4)[0] for i in range(20)]
    dwords_a2 = [struct.unpack_from("<I", b, d_start + 2 + i * 4)[0] for i in range(20)]
    words = [struct.unpack_from("<H", b, d_start + i * 2)[0] for i in range(40)]

    lines = ["# mdcache Command Blob Notes", "", "Date: 2026-02-16", ""]
    lines.append("## 1) Token Blob Slice")
    lines.append(f"- file_off: `0x{blob_off:05x}`")
    lines.append("```text")
    lines.append("".join(chr(c) if 32 <= c < 127 else "." for c in blob))
    lines.append("```")
    lines.append("")

    lines.append("## 2) Relocation hits near blob")
    lines.append("| rel# | ptr_cell | far(off:seg) | target | preview |")
    lines.append("| --- | --- | --- | --- | --- |")
    for r in rel_hits:
        i, ptr_cell, offw, segw, target, asc = r
        lines.append(
            f"| {i} | 0x{ptr_cell:05x} | {offw:04x}:{segw:04x} | 0x{target:05x} | {asc[:48]} |"
        )
    lines.append("")

    lines.append("## 3) Candidate descriptor words (`0x0d0c8..`)")
    lines.append("| idx | file_off | word_hex |")
    lines.append("| --- | --- | --- |")
    for i, v in enumerate(words):
        lines.append(f"| {i:02d} | 0x{d_start + i*2:05x} | 0x{v:04x} |")
    lines.append("")
    lines.append("## 4) Candidate descriptor dwords by alignment")
    lines.append("| idx | a0_file_off | a0_dword | a2_file_off | a2_dword |")
    lines.append("| --- | --- | --- | --- | --- |")
    for i in range(12):
        lines.append(
            f"| {i:02d} | 0x{d_start + i*4:05x} | 0x{dwords_a0[i]:08x} | "
            f"0x{d_start + 2 + i*4:05x} | 0x{dwords_a2[i]:08x} |"
        )
    lines.append("")
    lines.append("Interpretation (conservative):")
    lines.append("- Blob clearly contains command tokens: `ON`, `OFF`, `IS`, `FLUSH`, `?`.")
    lines.append("- Relocation #115 points to this parser-related blob region.")
    lines.append("- Relocations #127..#129 point to code offset `0x13a9` (stub-like `retf` body).")
    lines.append("- Adjacent lanes likely represent parser/dispatch descriptors,")
    lines.append("  but exact struct alignment/field semantics are not yet proven.")

    Path("analysis/mdcache_cmd_blob.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("wrote analysis/mdcache_cmd_blob.md")


if __name__ == "__main__":
    main()

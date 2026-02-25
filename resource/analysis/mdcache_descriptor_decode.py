#!/usr/bin/env python3
from __future__ import annotations

import struct
from pathlib import Path


def find_prologue(mem: bytes, addr: int, back: int = 48) -> int | None:
    lo = max(0, addr - back)
    for i in range(addr, lo - 1, -1):
        if i + 2 < len(mem) and mem[i] == 0x55 and mem[i + 1] == 0x8B and mem[i + 2] == 0xEC:
            return i
    return None


def read_z_tokens(data: bytes, off: int, count: int = 8) -> list[str]:
    out: list[str] = []
    i = off
    for _ in range(count):
        j = data.find(b"\x00", i)
        if j < 0:
            break
        tok = data[i:j]
        if not tok:
            break
        try:
            s = tok.decode("ascii", errors="ignore")
        except Exception:
            s = ""
        if s:
            out.append(s)
        i = j + 1
    return out


def main() -> None:
    p = Path("w31/extract/mdcache.exe")
    b = p.read_bytes()
    hdr = struct.unpack_from("<H", b, 0x08)[0] * 16
    mem = b[hdr:]  # memory-style linear view used by disasm addresses

    # Known cluster derived from relocation-guided blob analysis.
    base = 0x0D0AC

    cb0 = struct.unpack_from("<I", b, base + 0x00)[0]
    cb1 = struct.unpack_from("<I", b, base + 0x04)[0]
    cb2 = struct.unpack_from("<I", b, base + 0x08)[0]

    rec0 = base + 0x0E
    records = []
    for i in range(5):
        r = rec0 + i * 0x14
        d0, d1, d2, d3, d4 = struct.unpack_from("<IIIII", b, r)
        op_code = d0 & 0xFFFF
        op_index = (d0 >> 16) & 0xFFFF
        handler_low = d4 & 0xFFFF
        handler_abs = hdr + handler_low
        pg = find_prologue(mem, handler_abs)
        records.append(
            {
                "idx": i + 1,
                "rec_off": r,
                "d0": d0,
                "d1": d1,
                "d2": d2,
                "d3": d3,
                "d4": d4,
                "op_code": op_code,
                "op_index": op_index,
                "handler_low": handler_low,
                "handler_abs": handler_abs,
                "nearest_prologue": pg,
            }
        )

    tok_anchor = b.find(b":\\mdctl")
    tokens = read_z_tokens(b, tok_anchor + len(b":\\mdctl") + 1, count=10) if tok_anchor >= 0 else []

    lines = ["# mdcache Descriptor Decode (WS7)", "", "Date: 2026-02-16", ""]
    lines.append("## 1) Callback Trio")
    lines.append(f"- base: `0x{base:05x}`")
    lines.append(f"- cb0: `0x{cb0:08x}` (mem=0x{hdr + cb0:05x})")
    lines.append(f"- cb1: `0x{cb1:08x}` (mem=0x{hdr + cb1:05x})")
    lines.append(f"- cb2: `0x{cb2:08x}` (mem=0x{hdr + cb2:05x})")
    lines.append("")

    lines.append("## 2) 5x Descriptor Records (`0x14` stride)")
    lines.append("| idx | rec_off | d0 | d1 | d2 | d3 | d4(handler) | op_code | op_index | handler_mem | prologue_mem |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for r in records:
        pro = f"0x{r['nearest_prologue']:05x}" if r["nearest_prologue"] is not None else "n/a"
        lines.append(
            f"| {r['idx']} | 0x{r['rec_off']:05x} | 0x{r['d0']:08x} | 0x{r['d1']:08x} | 0x{r['d2']:08x} | "
            f"0x{r['d3']:08x} | 0x{r['d4']:08x} | 0x{r['op_code']:04x} | 0x{r['op_index']:04x} | "
            f"0x{r['handler_abs']:05x} | {pro} |"
        )
    lines.append("")

    lines.append("## 3) Token Order Near `:\\\\mdctl`")
    if tokens:
        for i, t in enumerate(tokens, 1):
            lines.append(f"- token_{i}: `{t}`")
    else:
        lines.append("- token extraction failed")
    lines.append("")

    lines.append("## 4) Conservative Interpretation")
    lines.append("- Descriptor block shape is highly regular (3 callbacks + 5 records).")
    lines.append("- Record `d4` low-word values map to valid code-region addresses.")
    lines.append("- Record `d0` low/high words look like `(op_code, op_index)` pairs.")
    lines.append("- Observed pairs: `(0209,0)`, `(020a,1)`, `(0202,2)`, `(0243,3)`, `(0242,4)`.")
    lines.append("- Token order near the same blob is `ON/OFF/IS/FLUSH/?`.")
    lines.append("- Therefore command-table linkage is strongly suggested but still not fully proven at instruction-level dispatch.")

    Path("analysis/mdcache_descriptor_decode.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("wrote analysis/mdcache_descriptor_decode.md")


if __name__ == "__main__":
    main()

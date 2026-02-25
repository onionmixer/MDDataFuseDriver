#!/usr/bin/env python3
from __future__ import annotations

import re
import struct
from pathlib import Path
import csv

from capstone import Cs, CS_ARCH_X86, CS_MODE_16


BASE_MEM = 0xDCD0  # inferred DS base for VD print format strings
RANGE_START = 0x0670
RANGE_END = 0x085C


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def cstr_at_mem(b: bytes, hdr: int, mem_off: int) -> str:
    fo = hdr + mem_off
    if fo < 0 or fo >= len(b):
        return ""
    s = b[fo : fo + 160].split(b"\x00", 1)[0]
    try:
        return s.decode("ascii", errors="ignore")
    except Exception:
        return ""


def main() -> None:
    p = Path("w31/extract/mdfsck.exe")
    b = p.read_bytes()
    hdr = u16(b, 0x08) * 16
    code = b[hdr:]

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(code[RANGE_START:RANGE_END], RANGE_START))

    rows = []
    out_md = [
        "# WS19 mdfsck VD Emit Map",
        "",
        "Date: 2026-02-17",
        "",
        "Scope: format-output sequence in `0x0670..0x085c`.",
        f"Inferred format-string base: `0x{BASE_MEM:04x}`.",
        "",
        "| call_mem | fmt_off | fmt_mem | fmt_text | pushed_globals_before_call |",
        "| --- | --- | --- | --- | --- |",
    ]

    for i, x in enumerate(ins):
        sig = f"{x.mnemonic} {x.op_str}".lower()
        if "lcall 0x3f7, 0x752" not in sig:
            continue

        window = ins[max(0, i - 10) : i]
        fmt_off = None
        globals_pushed: list[str] = []

        for w in window:
            s = f"{w.mnemonic} {w.op_str}".lower()
            m_fmt = re.search(r"push 0x([0-9a-f]+)$", s)
            if w.mnemonic == "push" and m_fmt:
                v = int(m_fmt.group(1), 16)
                # format offsets in this block are compact (not global pointers)
                if v < 0x1000:
                    fmt_off = v
            if w.mnemonic == "push":
                m_g = re.search(r"word ptr \[0x(5b[0-9a-f]{2})\]", s)
                if m_g:
                    globals_pushed.append("0x" + m_g.group(1))

        if fmt_off is None:
            continue

        fmt_mem = BASE_MEM + fmt_off
        fmt_text = cstr_at_mem(b, hdr, fmt_mem).replace("|", "\\|")
        gtxt = ",".join(globals_pushed)
        out_md.append(f"| 0x{x.address:04x} | 0x{fmt_off:03x} | 0x{fmt_mem:04x} | {fmt_text} | {gtxt} |")
        rows.append(
            {
                "call_mem": f"0x{x.address:04x}",
                "fmt_off": f"0x{fmt_off:03x}",
                "fmt_mem": f"0x{fmt_mem:04x}",
                "fmt_text": fmt_text,
                "pushed_globals_before_call": gtxt,
            }
        )

    out_md.append("")
    out_md.append("## Notes")
    out_md.append("- This maps printed VD field labels to global storage lanes (`0x5b40..`).")
    out_md.append("- It improves semantic labeling of globals but does not yet prove on-media byte offsets.")

    Path("analysis/ws19_mdfsck_vd_emit_map.md").write_text("\n".join(out_md) + "\n", encoding="utf-8")
    with open("analysis/ws19_mdfsck_vd_emit_map.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=["call_mem", "fmt_off", "fmt_mem", "fmt_text", "pushed_globals_before_call"],
        )
        w.writeheader()
        w.writerows(rows)
    print("wrote analysis/ws19_mdfsck_vd_emit_map.md and .csv")


if __name__ == "__main__":
    main()

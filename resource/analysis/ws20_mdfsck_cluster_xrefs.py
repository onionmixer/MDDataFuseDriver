#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import re
import csv

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

CL_START = 0x3994
CL_END = 0x3F4A


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def parse_target(op: str) -> int | None:
    s = op.strip().lower()
    if s.startswith("0x"):
        try:
            return int(s, 16)
        except ValueError:
            return None
    return None


def main() -> None:
    p = Path("w31/extract/mdfsck.exe")
    b = p.read_bytes()
    hdr = u16(b, 0x08) * 16
    code = b[hdr:]

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(code, 0))

    xrefs = []
    for i in ins:
        if i.mnemonic not in ("call", "lcall"):
            continue
        tgt = parse_target(i.op_str)
        if tgt is None:
            continue
        if CL_START <= tgt < CL_END:
            xrefs.append(
                {
                    "caller": f"0x{i.address:04x}",
                    "mnemonic": i.mnemonic,
                    "target": f"0x{tgt:04x}",
                    "op_str": i.op_str,
                }
            )

    # focus list for key helpers
    focus = [0x3A4C, 0x3ADC, 0x3CCA, 0x3DF2, 0x3E12, 0x3E32, 0x3E72, 0x3EF0, 0x3F4A]
    focus_calls = {f"0x{f:04x}": [] for f in focus}
    for i in ins:
        if i.mnemonic not in ("call", "lcall"):
            continue
        tgt = parse_target(i.op_str)
        if tgt is None:
            continue
        k = f"0x{tgt:04x}"
        if k in focus_calls:
            focus_calls[k].append(f"0x{i.address:04x}")

    lines = [
        "# WS20 mdfsck Cluster Xrefs",
        "",
        "Date: 2026-02-17",
        "",
        f"Target cluster: `0x{CL_START:04x}..0x{CL_END:04x}`.",
        "",
        "## Incoming call xrefs",
        "",
        "| caller | mnemonic | target | op_str |",
        "| --- | --- | --- | --- |",
    ]

    for r in xrefs:
        lines.append(f"| {r['caller']} | {r['mnemonic']} | {r['target']} | {r['op_str']} |")

    if not xrefs:
        lines.append("| (none) |  |  |  |")

    lines.extend([
        "",
        "## Focus helper callsites",
        "",
        "| helper | callers |",
        "| --- | --- |",
    ])

    for k in sorted(focus_calls.keys()):
        callers = ",".join(focus_calls[k]) if focus_calls[k] else ""
        lines.append(f"| {k} | {callers} |")

    lines.extend([
        "",
        "## Notes",
        "- This enumerates direct immediate call-style xrefs only.",
        "- Indirect calls/jump tables/function pointers are not resolved in this pass.",
    ])

    Path("analysis/ws20_mdfsck_cluster_xrefs.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    with open("analysis/ws20_mdfsck_cluster_xrefs.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["caller", "mnemonic", "target", "op_str"])
        w.writeheader()
        w.writerows(xrefs)

    print("wrote analysis/ws20_mdfsck_cluster_xrefs.md and .csv")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from __future__ import annotations

import csv
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_16
from capstone import CsError
from capstone.x86_const import X86_OP_IMM


TARGETS = {0x0209, 0x020A, 0x0202, 0x0243, 0x0242}
FILES = [
    Path("w31/extract/mdcache.exe"),
    Path("w31/extract/mdformat.exe"),
]


def mz_header_size(b: bytes) -> int:
    return struct.unpack_from("<H", b, 0x08)[0] * 16


def main() -> None:
    md = ["# WS12 Capstone Immediate Hit Scan", "", "Date: 2026-02-17", ""]
    rows: list[dict[str, str]] = []

    md_engine = Cs(CS_ARCH_X86, CS_MODE_16)
    md_engine.detail = True
    md_engine.skipdata = True

    for p in FILES:
        b = p.read_bytes()
        hdr = mz_header_size(b)
        code = b[hdr:]
        md.append(f"## {p.as_posix()}")
        md.append(f"- header_size: `0x{hdr:04x}`")
        hits = []

        for ins in md_engine.disasm(code, hdr):
            try:
                ops = ins.operands
            except CsError:
                continue
            for op in ops:
                if op.type != X86_OP_IMM:
                    continue
                v = op.imm & 0xFFFF
                if v in TARGETS:
                    hits.append((ins.address, ins.mnemonic, ins.op_str, v))
                    rows.append(
                        {
                            "file": p.as_posix(),
                            "insn_off": f"0x{ins.address:05x}",
                            "mnemonic": ins.mnemonic,
                            "op_str": ins.op_str,
                            "imm16": f"0x{v:04x}",
                        }
                    )

        md.append(f"- immediate hits: {len(hits)}")
        if hits:
            for a, m, o, v in hits[:40]:
                md.append(f"  - `0x{a:05x}`: `{m} {o}` (`0x{v:04x}`)")
        md.append("")

    md.append("## Note")
    md.append("- Linear disassembly over mixed code/data can miss hidden or alternate decode paths.")
    md.append("- However, low hit count here supports the descriptor-table interpretation for these values.")

    Path("analysis/ws12_capstone_imm_hits.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    with open("analysis/ws12_capstone_imm_hits.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["file", "insn_off", "mnemonic", "op_str", "imm16"])
        w.writeheader()
        w.writerows(rows)
    print("wrote analysis/ws12_capstone_imm_hits.md and .csv")


if __name__ == "__main__":
    main()

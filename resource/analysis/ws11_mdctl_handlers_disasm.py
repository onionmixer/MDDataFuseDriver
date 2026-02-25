#!/usr/bin/env python3
from __future__ import annotations

import os
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_16


TARGETS = {
    "w31/extract/mdcache.exe": [0x1818, 0x182C, 0x1840, 0x1854, 0x1868],
    "w31/extract/mdformat.exe": [0x2F5A, 0x2F6E, 0x2F82, 0x2F96, 0x2FAA],
}


def mz_header_size(b: bytes) -> int:
    return struct.unpack_from("<H", b, 0x08)[0] * 16


def disasm_block(b: bytes, start: int, size: int = 96) -> list[str]:
    code = b[start : start + size]
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    out: list[str] = []
    for ins in md.disasm(code, start):
        out.append(f"0x{ins.address:05x}: {ins.mnemonic} {ins.op_str}".rstrip())
    return out


def main() -> None:
    md = ["# WS11 MDCTL Handler Disassembly", "", "Date: 2026-02-17", ""]

    for fn, addrs in TARGETS.items():
        p = Path(fn)
        b = p.read_bytes()
        hdr = mz_header_size(b)
        md.append(f"## {fn}")
        md.append(f"- header_size: `0x{hdr:04x}`")
        for a in addrs:
            md.append(f"### handler @ `0x{a:05x}`")
            md.append("```asm")
            lines = disasm_block(b, a, 96)
            md.extend(lines[:24])
            md.append("```")
        md.append("")

    Path("analysis/ws11_mdctl_handlers_disasm.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("wrote analysis/ws11_mdctl_handlers_disasm.md")


if __name__ == "__main__":
    # optional sanity for local runs
    if "/tmp/mdh10_py" not in os.sys.path:
        pass
    main()

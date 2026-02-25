#!/usr/bin/env python3
from __future__ import annotations

import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_16


TARGET_FUNCS = [0x3994, 0x3A4C, 0x3ADC, 0x3B80]


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def disasm(code: bytes, start: int, n: int = 120) -> list[str]:
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    out: list[str] = []
    for i, ins in enumerate(md.disasm(code[start : start + 600], start)):
        out.append(f"0x{ins.address:04x}: {ins.mnemonic} {ins.op_str}".rstrip())
        if i + 1 >= n:
            break
    return out


def summarize(lines: list[str]) -> dict[str, list[str]]:
    k = {
        "frame_len": [],
        "type_byte": [],
        "subtype_byte": [],
        "tx_call": [],
        "rx_call": [],
        "error_str": [],
    }
    for ln in lines:
        s = ln.lower()
        if "push 0x20" in s or "push 0x208" in s or "push 0x4a" in s:
            k["frame_len"].append(ln)
        if "mov byte ptr [bp -" in s and ", 2" in s:
            k["type_byte"].append(ln)
        if "mov byte ptr [bp -" in s and (", 4" in s or ", 5" in s or ", 6" in s):
            k["subtype_byte"].append(ln)
        if "lcall 0x3f7, 0x1396" in s:
            k["tx_call"].append(ln)
        if "lcall 0x3f7, 0x1298" in s:
            k["rx_call"].append(ln)
        if "push 0x13f6" in s or "push 0x1401" in s or "push 0x1407" in s or "push 0x1412" in s or "push 0x1417" in s:
            k["error_str"].append(ln)
    return k


def main() -> None:
    p = Path("w31/extract/mdfsck.exe")
    b = p.read_bytes()
    hdr = u16(b, 0x08) * 16
    code = b[hdr:]

    md_lines = [
        "# WS14 mdfsck Frame Builder Audit",
        "",
        "Date: 2026-02-17",
        "",
        "Scope: `w31/extract/mdfsck.exe` command-frame builder functions.",
        "",
    ]

    for fn in TARGET_FUNCS:
        lines = disasm(code, fn, 120)
        sig = summarize(lines)
        md_lines.append(f"## func `0x{fn:04x}`")
        if sig["frame_len"]:
            md_lines.append("- frame length setup:")
            for x in sig["frame_len"][:6]:
                md_lines.append(f"  - `{x}`")
        if sig["type_byte"]:
            md_lines.append("- frame type byte setup:")
            for x in sig["type_byte"][:4]:
                md_lines.append(f"  - `{x}`")
        if sig["subtype_byte"]:
            md_lines.append("- frame subtype byte setup:")
            for x in sig["subtype_byte"][:4]:
                md_lines.append(f"  - `{x}`")
        if sig["tx_call"] or sig["rx_call"]:
            md_lines.append("- transport calls:")
            for x in sig["tx_call"][:3]:
                md_lines.append(f"  - TX `{x}`")
            for x in sig["rx_call"][:3]:
                md_lines.append(f"  - RX `{x}`")
        if sig["error_str"]:
            md_lines.append("- error/report string-id pushes:")
            for x in sig["error_str"][:6]:
                md_lines.append(f"  - `{x}`")
        md_lines.append("")
        md_lines.append("```asm")
        md_lines.extend(lines[:80])
        md_lines.append("```")
        md_lines.append("")

    md_lines.append("## Conservative Findings")
    md_lines.append("- `mdfsck` uses structured request buffers with explicit fixed lengths (`0x20`, `0x208`, `0x4a`).")
    md_lines.append("- Multiple builders initialize leading bytes to `type=2` and subtype values (`4`, `5`, `6`) before transport calls.")
    md_lines.append("- Calls to imported transport entry points (`0x3f7:0x1396` then `0x3f7:0x1298`) are consistent with request/response framing.")
    md_lines.append("- This constrains command payload structure shape but does not yet map these frame subtypes to MDCTL opcode IDs.")

    Path("analysis/ws14_mdfsck_frame_builders.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    print("wrote analysis/ws14_mdfsck_frame_builders.md")


if __name__ == "__main__":
    main()

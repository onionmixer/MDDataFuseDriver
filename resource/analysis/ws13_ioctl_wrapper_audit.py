#!/usr/bin/env python3
from __future__ import annotations

import re
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_16


TARGETS = {
    "w31/extract/mdcache.exe": 0x15B6,
    "w31/extract/mdformat.exe": 0x2439,
}


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def find_prologue(code: bytes, addr: int, back: int = 64) -> int:
    lo = max(0, addr - back)
    for i in range(addr, lo - 1, -1):
        if i + 2 < len(code) and code[i] == 0x55 and code[i + 1] == 0x8B and code[i + 2] == 0xEC:
            return i
    return addr


def disasm_lines(code: bytes, start: int, n: int = 48) -> list[str]:
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    out: list[str] = []
    for i, ins in enumerate(md.disasm(code[start : start + 320], start)):
        out.append(f"0x{ins.address:04x}: {ins.mnemonic} {ins.op_str}".rstrip())
        if i + 1 >= n:
            break
    return out


def find_near_call_xrefs(code: bytes, target: int) -> list[int]:
    out: list[int] = []
    n = len(code)
    for i in range(0, n - 2):
        if code[i] != 0xE8:
            continue
        rel = struct.unpack_from("<h", code, i + 1)[0]
        dst = (i + 3 + rel) & 0xFFFF
        if dst == target:
            out.append(i)
    return out


def decode_push_window(code: bytes, call_off: int, window: int = 40) -> list[str]:
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    s = max(0, call_off - window)
    lines = []
    for ins in md.disasm(code[s : call_off + 8], s):
        if ins.address > call_off:
            break
        lines.append(f"0x{ins.address:04x}: {ins.mnemonic} {ins.op_str}".rstrip())
    return lines


def infer_al_immediate(push_lines: list[str]) -> str:
    # Typical pattern: mov ax, <imm>; push ax  OR xor ax,ax; push ax
    # We inspect last ~6 lines before call.
    tail = push_lines[-8:]
    al = None
    for i, ln in enumerate(tail):
        if ": mov ax, " in ln:
            m = re.search(r"mov ax, 0x([0-9a-fA-F]+)", ln)
            if m:
                al = int(m.group(1), 16) & 0xFFFF
        if ": xor ax, ax" in ln:
            al = 0
    if al is None:
        return "unknown"
    return f"0x{al:04x}"


def main() -> None:
    md = ["# WS13 DOS IOCTL Wrapper Audit", "", "Date: 2026-02-17", ""]

    for fn, wrapper in TARGETS.items():
        p = Path(fn)
        b = p.read_bytes()
        hdr = u16(b, 0x08) * 16
        code = b[hdr:]

        pro = find_prologue(code, wrapper, 64)
        lines = disasm_lines(code, pro, 52)
        xrefs = find_near_call_xrefs(code, wrapper)

        md.append(f"## {fn}")
        md.append(f"- wrapper_mem: `0x{wrapper:04x}`")
        md.append(f"- wrapper_prologue: `0x{pro:04x}`")
        md.append(f"- near_call_xrefs: {len(xrefs)}")
        md.append("")
        md.append("### Wrapper Body")
        md.append("```asm")
        md.extend(lines)
        md.append("```")
        md.append("")

        md.append("### Callsite Samples")
        if not xrefs:
            md.append("- none")
        else:
            for i, xo in enumerate(xrefs[:8], 1):
                push_lines = decode_push_window(code, xo, 44)
                al_guess = infer_al_immediate(push_lines)
                md.append(f"- call_{i}: at `0x{xo:04x}`, inferred AL arg `{al_guess}`")
                md.append("```asm")
                md.extend(push_lines)
                md.append("```")
        md.append("")

    md.append("## Findings")
    md.append("- Both wrappers set `AH=0x44` and call `int 0x21` (DOS IOCTL/device control class).")
    md.append("- Both wrappers load `AL` from stack argument (function code is caller-supplied).")
    md.append("- `mdcache` direct xrefs show `AL=0` and `AL=1` style callsites; no direct evidence here for `AL=2+`.")
    md.append("- This supports a conservative split: generic DOS IOCTL transport is confirmed;")
    md.append("  private MDCTL payload schema remains unresolved.")

    Path("analysis/ws13_ioctl_wrapper_audit.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("wrote analysis/ws13_ioctl_wrapper_audit.md")


if __name__ == "__main__":
    main()

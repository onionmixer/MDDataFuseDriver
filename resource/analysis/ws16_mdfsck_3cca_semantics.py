#!/usr/bin/env python3
from __future__ import annotations

import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_16


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def disasm_range(code: bytes, start: int, end: int) -> list[str]:
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    out: list[str] = []
    for ins in md.disasm(code[start:end], start):
        out.append(f"0x{ins.address:04x}: {ins.mnemonic} {ins.op_str}".rstrip())
    return out


def find_lines(lines: list[str], keys: list[str]) -> list[str]:
    out: list[str] = []
    for ln in lines:
        s = ln.lower()
        if any(k in s for k in keys):
            out.append(ln)
    return out


def main() -> None:
    p = Path("w31/extract/mdfsck.exe")
    b = p.read_bytes()
    hdr = u16(b, 0x08) * 16
    code = b[hdr:]

    f_3cca = disasm_range(code, 0x3CCA, 0x3DF2)
    f_3df2 = disasm_range(code, 0x3DF2, 0x3E12)
    f_3e12 = disasm_range(code, 0x3E12, 0x3E32)

    core_keys = find_lines(
        f_3cca,
        [
            "mov si, word ptr [bp + 0x10]",
            "shl si, 0xb",
            "mov byte ptr es:[bx], 1",
            "cmp word ptr [bp + 0x14], 1",
            "add cl, 0x18",
            "mov word ptr es:[bx + 0x10], cx",
            "mov word ptr es:[bx + 0x12], si",
            "mov word ptr es:[bx + 0x14], cx",
            "cmp word ptr [bp + 0x14], ax",
            "rep movsw",
            "lcall 0x3f7, 0x1396",
            "lcall 0x3f7, 0x1298",
            "cmp word ptr [bp + 0x14], 0",
        ],
    )

    md = ["# WS16 mdfsck `0x3cca` Semantics", "", "Date: 2026-02-17", ""]
    md.append("## 1) Wrapper Entry Points")
    md.append("- `0x3df2` pushes literal `0` then forwards args to `0x3cca`.")
    md.append("- `0x3e12` pushes literal `1` then forwards args to `0x3cca`.")
    md.append("")
    md.append("### `0x3df2`")
    md.append("```asm")
    md.extend(f_3df2)
    md.append("```")
    md.append("")
    md.append("### `0x3e12`")
    md.append("```asm")
    md.extend(f_3e12)
    md.append("```")
    md.append("")

    md.append("## 2) Core `0x3cca` Evidence Lines")
    md.append("```asm")
    md.extend(core_keys)
    md.append("```")
    md.append("")

    md.append("## 3) Conservative Parameter Interpretation")
    md.append("- `arg@+14` is a direction flag injected by wrappers (`0` vs `1`).")
    md.append("- Request header starts with `type=1` (`mov byte ptr es:[bx],1`).")
    md.append("- Header subtype-like byte is derived from direction/mode path:")
    md.append("  `cmp mode,1; sbb cl,cl; and cl,0xfe; add cl,0x18` => mode `0 -> 0x16`, mode `1 -> 0x18`.")
    md.append("- `arg@+10` is transformed by `<<11` and used in length math (`len = (arg<<11)+0x18`).")
    md.append("- For `arg@+14 != 0`, payload is copied from caller buffer into tx frame before send.")
    md.append("- Send call: `lcall 0x3f7,0x1396`; receive call: `lcall 0x3f7,0x1298`.")
    md.append("- For `arg@+14 == 0`, payload is copied from rx frame back to caller buffer.")
    md.append("")
    md.append("## 4) Limits")
    md.append("- This establishes request/response direction semantics and frame-length behavior.")
    md.append("- It does not yet identify exact field names for header words at `+0x10/+0x12/+0x14`.")
    md.append("- It does not by itself map these fields to on-disk VD member offsets.")

    Path("analysis/ws16_mdfsck_3cca_semantics.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("wrote analysis/ws16_mdfsck_3cca_semantics.md")


if __name__ == "__main__":
    main()

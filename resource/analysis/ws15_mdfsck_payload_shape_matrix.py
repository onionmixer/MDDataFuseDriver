#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_16


FUNCS = [
    0x3CCA,  # variable len (mode-dependent subtype: 0x16/0x18) type=1
    0x3E32,  # calls 3a4c then 3adc
    0x3E72,  # len 0x11 type=2 sub=8
    0x3EF0,  # len 0x17 type=1 sub=0x24 (+ byte @-7 = 2)
    0x3F4A,  # len 0x10 type=1 sub=7
]
RANGES = {
    0x3CCA: (0x3CCA, 0x3DF2),
    0x3E32: (0x3E32, 0x3E72),
    0x3E72: (0x3E72, 0x3EF0),
    0x3EF0: (0x3EF0, 0x3F4A),
    0x3F4A: (0x3F4A, 0x3F7D),
}


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def disasm_fn(code: bytes, start: int, end: int, max_insn: int = 300) -> list[tuple[int, str, str]]:
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    out = []
    for i, ins in enumerate(md.disasm(code[start:end], start)):
        out.append((ins.address, ins.mnemonic, ins.op_str))
        if i + 1 >= max_insn:
            break
    return out


def scan_features(insns: list[tuple[int, str, str]]) -> dict[str, str]:
    lengths: list[str] = []
    type_vals: list[str] = []
    sub_vals: list[str] = []
    extra_vals: list[str] = []
    tx = 0
    rx = 0
    nested: list[str] = []

    for a, m, o in insns:
        s = f"{m} {o}".lower()
        if m == "push" and o.startswith("0x"):
            v = int(o, 16)
            if v in (0x10, 0x11, 0x17, 0x20, 0x4A):
                lengths.append(hex(v))
        if "mov byte ptr [bp -" in s and ", " in s:
            mdisp = re.search(r"\[bp - 0x([0-9a-f]+)\]", s)
            disp = int(mdisp.group(1), 16) if mdisp else None
            try:
                imm = int(s.rsplit(", ", 1)[1], 0)
            except Exception:
                continue
            # Header type/subtype are written at frame base and base+1.
            if disp in (0x4A, 0x20, 0x12, 0x18, 0x10, 0x208) and imm in (1, 2):
                type_vals.append(hex(imm))
            elif disp in (0x49, 0x1F, 0x11, 0x17, 0x0F, 0x207) and imm in (4, 5, 6, 7, 8, 0x18, 0x19, 0x24):
                sub_vals.append(hex(imm))
            else:
                extra_vals.append(hex(imm))
        if s == "mov byte ptr es:[bx], 1":
            type_vals.append("0x1")
        if "add cl, 0x18" in s:
            sub_vals.append("0x16/0x18")
        if "lcall 0x3f7, 0x1396" in s:
            tx += 1
        if "lcall 0x3f7, 0x1298" in s:
            rx += 1
        if m == "call" and o.startswith("0x"):
            nested.append(o)

    def uniq(xs: list[str]) -> str:
        out: list[str] = []
        for x in xs:
            if x not in out:
                out.append(x)
        return ",".join(out)

    return {
        "lengths": uniq(lengths),
        "type_values": uniq(type_vals),
        "sub_values": uniq(sub_vals),
        "extra_values": uniq(extra_vals),
        "tx_calls": str(tx),
        "rx_calls": str(rx),
        "nested_calls": uniq(nested),
    }


def main() -> None:
    p = Path("w31/extract/mdfsck.exe")
    b = p.read_bytes()
    hdr = u16(b, 0x08) * 16
    code = b[hdr:]

    rows = []
    md_lines = ["# WS15 mdfsck Payload Shape Matrix", "", "Date: 2026-02-17", ""]
    md_lines.append("| func_mem | lengths | type_values | sub_values | tx_calls | rx_calls | nested_calls |")
    md_lines.append("| --- | --- | --- | --- | --- | --- | --- |")

    for f in FUNCS:
        s, e = RANGES[f]
        ins = disasm_fn(code, s, e, 500)
        feat = scan_features(ins)
        row = {"func_mem": f"0x{f:04x}", **feat}
        rows.append(row)
        md_lines.append(
            f"| {row['func_mem']} | {row['lengths']} | {row['type_values']} | {row['sub_values']} | "
            f"{row['tx_calls']} | {row['rx_calls']} | {row['nested_calls']} |"
        )

    md_lines.append("")
    md_lines.append("## Notes")
    md_lines.append("- `0x3cca` uses `type=1` and computes subtype-like byte as `0x16/0x18` from mode arg.")
    md_lines.append("- `0x3e32` is an orchestrator that sequences `0x3a4c` then `0x3adc` (both `type=2` frame families).")
    md_lines.append("- `0x3e72` builds `type=2,sub=8,len=0x11` frame pair (tx+rx).")
    md_lines.append("- `0x3ef0` and `0x3f4a` are `type=1` control/info probes with compact frame lengths.")
    md_lines.append("- This matrix is payload-shape evidence only, not final opcode semantics.")

    Path("analysis/ws15_mdfsck_payload_shape_matrix.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    with open("analysis/ws15_mdfsck_payload_shape_matrix.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=["func_mem", "lengths", "type_values", "sub_values", "extra_values", "tx_calls", "rx_calls", "nested_calls"],
        )
        w.writeheader()
        w.writerows(rows)
    print("wrote analysis/ws15_mdfsck_payload_shape_matrix.md and .csv")


if __name__ == "__main__":
    main()

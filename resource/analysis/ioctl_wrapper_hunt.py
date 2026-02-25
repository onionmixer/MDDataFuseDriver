#!/usr/bin/env python3
from __future__ import annotations

import csv
import struct
from dataclasses import dataclass
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_16


TARGETS = [
    Path("w31/extract/mdcache.exe"),
    Path("w31/extract/mdfsex.exe"),
    Path("w31/extract/mdfsck.exe"),
    Path("w31/extract/mdformat.exe"),
    Path("w31/extract/mdmgr.exe"),
]


@dataclass
class Wrapper:
    int21_at: int
    start_at: int | None
    al_bp_disp: int | None
    bx_bp_disp: int | None
    cx_bp_disp: int | None
    dx_bp_disp: int | None


def mz_entry_offset(data: bytes) -> int:
    e_cparhdr = struct.unpack_from("<H", data, 0x08)[0]
    ip = struct.unpack_from("<H", data, 0x14)[0]
    cs = struct.unpack_from("<H", data, 0x16)[0]
    return e_cparhdr * 16 + cs * 16 + ip


def parse_bp_disp(op_str: str) -> int | None:
    s = op_str.lower().replace("ptr", "").replace(" ", "")
    if "[bp+" in s:
        v = s.split("[bp+", 1)[1].split("]", 1)[0]
        try:
            return int(v, 16) if v.startswith("0x") else int(v, 10)
        except ValueError:
            return None
    if "[bp-" in s:
        v = s.split("[bp-", 1)[1].split("]", 1)[0]
        try:
            n = int(v, 16) if v.startswith("0x") else int(v, 10)
            return -n
        except ValueError:
            return None
    if "[bp]" in s:
        return 0
    return None


def find_fn_start(ins: list, idx: int, window: int = 60) -> int | None:
    lo = max(0, idx - window)
    for j in range(idx, lo - 1, -1):
        if ins[j].mnemonic == "push" and ins[j].op_str.lower() == "bp":
            if j + 1 < len(ins):
                n = ins[j + 1]
                if n.mnemonic == "mov" and n.op_str.lower().replace(" ", "") == "bp,sp":
                    return ins[j].address
    return None


def collect_wrappers(ins: list) -> list[Wrapper]:
    out: list[Wrapper] = []
    for i, x in enumerate(ins):
        if x.mnemonic != "int" or x.op_str.strip().lower() != "0x21":
            continue
        prev = ins[max(0, i - 14):i]
        has_ah44 = any(
            p.mnemonic == "mov" and ("ah, 0x44" in p.op_str.lower() or "ax, 0x4400" in p.op_str.lower())
            for p in prev
        )
        if not has_ah44:
            continue

        al_bp = bx_bp = cx_bp = dx_bp = None
        for p in prev:
            txt = p.op_str.lower()
            if p.mnemonic == "mov" and txt.startswith("al,"):
                al_bp = parse_bp_disp(txt.split(",", 1)[1])
            elif p.mnemonic == "mov" and txt.startswith("bx,"):
                bx_bp = parse_bp_disp(txt.split(",", 1)[1])
            elif p.mnemonic == "mov" and txt.startswith("cx,"):
                cx_bp = parse_bp_disp(txt.split(",", 1)[1])
            elif p.mnemonic == "lds" and txt.startswith("dx,"):
                dx_bp = parse_bp_disp(txt.split(",", 1)[1])
        out.append(
            Wrapper(
                int21_at=x.address,
                start_at=find_fn_start(ins, i),
                al_bp_disp=al_bp,
                bx_bp_disp=bx_bp,
                cx_bp_disp=cx_bp,
                dx_bp_disp=dx_bp,
            )
        )
    return out


def collect_callers(ins: list, target: int) -> list[tuple[int, list]]:
    hits = []
    for i, x in enumerate(ins):
        if x.mnemonic != "call":
            continue
        op = x.op_str.strip().lower()
        if not op.startswith("0x"):
            continue
        try:
            dst = int(op, 16)
        except ValueError:
            continue
        if dst != target:
            continue
        ctx = ins[max(0, i - 14):i]
        hits.append((x.address, ctx))
    return hits


def summarize_pushes(ctx: list) -> str:
    vals: list[str] = []
    for c in ctx:
        if c.mnemonic != "push":
            continue
        op = c.op_str.strip().lower()
        if op.startswith("0x"):
            vals.append(op)
            continue
        if op in {"ax", "bx", "cx", "dx", "si", "di"}:
            vals.append(op)
            continue
        if op.startswith("word ptr"):
            vals.append(op.replace(" ", ""))
    return ",".join(vals)


def main() -> None:
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    md.detail = False

    rows = []
    lines = ["# DOS IOCTL Wrapper Hunt", "", "Date: 2026-02-16", ""]

    for p in TARGETS:
        if not p.exists():
            continue
        data = p.read_bytes()
        base = mz_entry_offset(data)
        ins = list(md.disasm(data[base:], base))
        wrappers = collect_wrappers(ins)
        lines.append(f"## {p}")
        lines.append(f"- decoded_insn_count: {len(ins)}")
        lines.append(f"- wrapper_candidates: {len(wrappers)}")
        if not wrappers:
            lines.append("")
            continue

        for widx, w in enumerate(wrappers, 1):
            lines.append(
                f"- wrapper_{widx}: int21=0x{w.int21_at:05x}, start={f'0x{w.start_at:05x}' if w.start_at is not None else 'n/a'}, "
                f"al=[bp+{w.al_bp_disp}] bx=[bp+{w.bx_bp_disp}] cx=[bp+{w.cx_bp_disp}] ldsdx=[bp+{w.dx_bp_disp}]"
            )
            if w.start_at is None:
                continue
            callers = collect_callers(ins, w.start_at)
            lines.append(f"  - direct_callers: {len(callers)}")
            for caddr, ctx in callers[:40]:
                pushes = summarize_pushes(ctx)
                lines.append(f"    - call@0x{caddr:05x} pushes={pushes if pushes else '-'}")
                rows.append(
                    {
                        "file": str(p),
                        "wrapper_start": f"0x{w.start_at:05x}",
                        "int21_at": f"0x{w.int21_at:05x}",
                        "call_at": f"0x{caddr:05x}",
                        "al_bp_disp": w.al_bp_disp,
                        "bx_bp_disp": w.bx_bp_disp,
                        "cx_bp_disp": w.cx_bp_disp,
                        "dx_bp_disp": w.dx_bp_disp,
                        "caller_pushes": pushes,
                    }
                )
        lines.append("")

    Path("analysis/ioctl_wrapper_hunt.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    with Path("analysis/ioctl_wrapper_hunt.csv").open("w", newline="", encoding="utf-8") as f:
        wr = csv.DictWriter(
            f,
            fieldnames=[
                "file",
                "wrapper_start",
                "int21_at",
                "call_at",
                "al_bp_disp",
                "bx_bp_disp",
                "cx_bp_disp",
                "dx_bp_disp",
                "caller_pushes",
            ],
        )
        wr.writeheader()
        wr.writerows(rows)
    print("wrote analysis/ioctl_wrapper_hunt.md")
    print("wrote analysis/ioctl_wrapper_hunt.csv")


if __name__ == "__main__":
    main()

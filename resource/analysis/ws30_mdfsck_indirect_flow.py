#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

CL_START = 0x3994
CL_END = 0x3F4A


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def main() -> None:
    p = Path("w31/extract/mdfsck.exe")
    b = p.read_bytes()
    hdr = u16(b, 0x08) * 16
    img = b[hdr:]

    cs = u16(b, 0x16)
    cs_base = cs << 4
    ds_seg = u16(img, cs_base + 0x12E)
    ds_base = ds_seg << 4

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(img, 0))
    # Focus windows capture parser/runtime blocks that may be skipped in full linear pass.
    for s, e in [(0x4040, 0x4270), (0x44f0, 0x4540), (0x4AC0, 0x4B40), (0x5200, 0x5340)]:
        ins.extend(list(md.disasm(img[s:e], s)))
    # De-duplicate by (address,mnemonic,op_str)
    uniq = {}
    for i in ins:
        uniq[(i.address, i.mnemonic, i.op_str)] = i
    ins = [uniq[k] for k in sorted(uniq.keys())]

    # collect indirect call/jmp sites
    rows: list[dict[str, str]] = []
    for i in ins:
        if i.mnemonic not in ("call", "jmp", "lcall", "ljmp"):
            continue
        op = i.op_str.replace(" ", "")
        if "[" not in op:
            continue

        slot_off = None
        slot_seg = "ds"
        if "cs:[bx+0xb30]" in op.lower():
            # jump table dispatch case at 0x4b03
            slot_seg = "cs"
            rows.append(
                {
                    "site": f"0x{i.address:04x}",
                    "insn": f"{i.mnemonic} {i.op_str}",
                    "slot_seg": slot_seg,
                    "slot_off": "0x0b30+bx",
                    "slot_lin": f"0x{cs_base + 0x0B30:04x}",
                    "resolved": "jump-table",
                    "resolved_target_lin": "local parser states",
                    "hits_cluster": "no",
                    "note": "table entries decode to offsets 0x0b98..0x0c7c (linear 0x4b08..0x4bec)",
                }
            )
            continue

        # patterns like word ptr [0x1960], [di]
        m = re.search(r"\[([^\]]+)\]", i.op_str.lower())
        expr = m.group(1).replace(" ", "") if m else ""
        if expr == "di":
            rows.append(
                {
                    "site": f"0x{i.address:04x}",
                    "insn": f"{i.mnemonic} {i.op_str}",
                    "slot_seg": "unknown",
                    "slot_off": "di",
                    "slot_lin": "runtime",
                    "resolved": "indirect-runtime",
                    "resolved_target_lin": "unknown",
                    "hits_cluster": "unknown",
                    "note": "register-based far call; requires runtime trace",
                }
            )
            continue
        if expr.startswith("0x"):
            try:
                slot_off = int(expr, 16)
            except ValueError:
                slot_off = None

        if slot_off is None:
            continue

        # default DS-based pointer slot
        slot_lin = ds_base + slot_off
        if slot_lin + 4 > len(img):
            rows.append(
                {
                    "site": f"0x{i.address:04x}",
                    "insn": f"{i.mnemonic} {i.op_str}",
                    "slot_seg": slot_seg,
                    "slot_off": f"0x{slot_off:04x}",
                    "slot_lin": f"0x{slot_lin:04x}",
                    "resolved": "oob",
                    "resolved_target_lin": "",
                    "hits_cluster": "unknown",
                    "note": "slot outside image",
                }
            )
            continue

        w0 = u16(img, slot_lin)
        w1 = u16(img, slot_lin + 2)

        if i.mnemonic in ("call", "jmp"):
            tgt_off = w0
            tgt_lin = cs_base + tgt_off
            hit = CL_START <= tgt_lin < CL_END
            rows.append(
                {
                    "site": f"0x{i.address:04x}",
                    "insn": f"{i.mnemonic} {i.op_str}",
                    "slot_seg": "ds",
                    "slot_off": f"0x{slot_off:04x}",
                    "slot_lin": f"0x{slot_lin:04x}",
                    "resolved": f"near 0x{tgt_off:04x}",
                    "resolved_target_lin": f"0x{tgt_lin:04x}",
                    "hits_cluster": "yes" if hit else "no",
                    "note": "",
                }
            )
        else:
            # far pointer: off:seg
            tgt_off = w0
            tgt_seg = w1
            if tgt_off == 0 and tgt_seg == 0:
                resolved = "far 0000:0000"
                tgt_lin = ""
                hit = False
                note = "null far ptr (likely runtime filled)"
            elif tgt_off == 0xFFFF and tgt_seg == 0xFFFF:
                resolved = "far ffff:ffff"
                tgt_lin = ""
                hit = False
                note = "sentinel far ptr (likely runtime filled)"
            else:
                lin = (tgt_seg << 4) + tgt_off
                resolved = f"far {tgt_seg:04x}:{tgt_off:04x}"
                tgt_lin = f"0x{lin:04x}"
                hit = CL_START <= lin < CL_END
                note = ""
            rows.append(
                {
                    "site": f"0x{i.address:04x}",
                    "insn": f"{i.mnemonic} {i.op_str}",
                    "slot_seg": "ds",
                    "slot_off": f"0x{slot_off:04x}",
                    "slot_lin": f"0x{slot_lin:04x}",
                    "resolved": resolved,
                    "resolved_target_lin": tgt_lin,
                    "hits_cluster": "yes" if hit else "no",
                    "note": note,
                }
            )

    # dedupe stable row order by site then insn
    rows = sorted(rows, key=lambda r: (r["site"], r["insn"]))

    out_md = [
        "# WS30 mdfsck Indirect Flow",
        "",
        "Date: 2026-02-17",
        "",
        "## Segment Bases",
        f"- `CS=0x{cs:04x}` => `CS_base=0x{cs_base:04x}`",
        f"- `DS` init from `cs:[0x012e]=0x{ds_seg:04x}` => `DS_base=0x{ds_base:04x}`",
        "",
        "## Indirect call/jump resolution",
        "",
        "| site | insn | slot_seg | slot_off | slot_lin | resolved | resolved_target_lin | hits_cluster | note |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    for r in rows:
        out_md.append(
            f"| {r['site']} | {r['insn']} | {r['slot_seg']} | {r['slot_off']} | {r['slot_lin']} | "
            f"{r['resolved']} | {r['resolved_target_lin']} | {r['hits_cluster']} | {r['note']} |"
        )

    out_md.extend(
        [
            "",
            "## Conclusions",
            "- Resolved indirect pointers in this pass do not target `0x3994..0x3f4a`.",
            "- `lcall [0x1752/0x175a/0x175e/0x1766]` resolves to `0x3f7:0x02ce` (linear `0x423e`) at image-init state.",
            "- `call word ptr [0x1960/0x1962/0x1964]` resolves to near offset `0x00f2` (linear `0x4062`) at image-init state.",
            "- Remaining unresolved runtime vectors (`[0x196c]`, `[di]`, sentinel slots) require runtime tracing.",
        ]
    )

    Path("analysis/ws30_mdfsck_indirect_flow.md").write_text("\n".join(out_md) + "\n", encoding="utf-8")
    with open("analysis/ws30_mdfsck_indirect_flow.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "site",
                "insn",
                "slot_seg",
                "slot_off",
                "slot_lin",
                "resolved",
                "resolved_target_lin",
                "hits_cluster",
                "note",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print("wrote analysis/ws30_mdfsck_indirect_flow.md and .csv")


if __name__ == "__main__":
    main()

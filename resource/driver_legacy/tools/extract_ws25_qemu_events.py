#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path


RE_GPRS = re.compile(
    r"EAX=([0-9A-F]{8}) EBX=([0-9A-F]{8}) ECX=([0-9A-F]{8}) EDX=([0-9A-F]{8})"
)
RE_EIP = re.compile(r"EIP=([0-9A-F]{8})", re.IGNORECASE)
RE_ESP = re.compile(r"ESP=([0-9A-F]{8})", re.IGNORECASE)
RE_SEG = re.compile(r"^(CS|DS|SS) =([0-9A-F]{4}) ", re.IGNORECASE)


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract WS25-like rows from QEMU -d int,cpu log")
    ap.add_argument("--log", required=True, help="qemu.log path")
    ap.add_argument("--out", required=True, help="output csv path")
    ap.add_argument("--tool", default="autoexec_short", help="tool label")
    ap.add_argument("--site", default="int21_44xx", help="site label")
    ap.add_argument("--limit", type=int, default=200, help="max rows")
    ap.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="keep rows even when CS:EIP / SS:SP context is missing",
    )
    args = ap.parse_args()

    lines = Path(args.log).read_text(encoding="utf-8", errors="replace").splitlines()
    rows: list[dict[str, str]] = []

    for i, ln in enumerate(lines):
        m = RE_GPRS.search(ln)
        if not m:
            continue

        eax = int(m.group(1), 16)
        ax = eax & 0xFFFF
        if not (0x4400 <= ax <= 0x44FF):
            continue

        ebx = int(m.group(2), 16)
        ecx = int(m.group(3), 16)
        edx = int(m.group(4), 16)

        eip = ""
        esp = ""
        cs = ""
        ds = ""
        ss = ""
        lo = max(0, i - 10)
        hi = min(len(lines), i + 40)
        for j in range(lo, hi):
            mm = RE_EIP.search(lines[j])
            if mm and not eip:
                eip = mm.group(1)
            me = RE_ESP.search(lines[j])
            if me and not esp:
                esp = me.group(1)
            ms = RE_SEG.match(lines[j].strip())
            if ms:
                seg, val = ms.group(1), ms.group(2)
                seg = seg.upper()
                if seg == "CS":
                    cs = val
                elif seg == "DS":
                    ds = val
                elif seg == "SS":
                    ss = val

        cs_ip = f"{cs.lower()}:{eip[-4:].lower()}" if cs and eip else ""
        buf_ptr = f"{ds.lower()}:{edx & 0xFFFF:04x}" if ds else ""
        ss_sp = f"{ss.lower()}:{int(esp,16)&0xFFFF:04x}" if ss and esp else ""

        if not args.allow_incomplete and (not cs_ip or not ss_sp):
            continue

        rows.append(
            {
                "tool": args.tool,
                "site": args.site,
                "phase": "pre",
                "cs_ip": cs_ip,
                "ax": f"0x{ax:04x}",
                "bx": f"0x{ebx & 0xFFFF:04x}",
                "cx": f"0x{ecx & 0xFFFF:04x}",
                "dx": f"0x{edx & 0xFFFF:04x}",
                "ds": f"0x{ds.lower()}" if ds else "",
                "es": "",
                "ss_sp": ss_sp,
                "buf_ptr": buf_ptr,
                "buf_len": f"0x{ecx & 0xFFFF:04x}",
                "buf_hex_prefix": "",
                "notes": f"ax_subfunc=0x{ax & 0xFF:02x}",
            }
        )
        if len(rows) >= args.limit:
            break

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "tool",
                "site",
                "phase",
                "cs_ip",
                "ax",
                "bx",
                "cx",
                "dx",
                "ds",
                "es",
                "ss_sp",
                "buf_ptr",
                "buf_len",
                "buf_hex_prefix",
                "notes",
            ],
        )
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {out} rows={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

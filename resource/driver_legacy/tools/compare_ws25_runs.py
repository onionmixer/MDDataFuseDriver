#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description="Compute stable WS25 lane signatures between two runs")
    ap.add_argument("--run1", required=True, help="run1 csv path")
    ap.add_argument("--run2", required=True, help="run2 csv path")
    ap.add_argument("--out", required=True, help="output intersection csv path")
    args = ap.parse_args()

    r1 = list(csv.DictReader(Path(args.run1).open(encoding="utf-8")))
    r2 = list(csv.DictReader(Path(args.run2).open(encoding="utf-8")))

    key_fields = ["ax", "bx", "cx", "dx", "ds", "buf_ptr", "buf_len"]
    key = lambda row: tuple(row[k] for k in key_fields)
    s1 = {key(r) for r in r1}
    s2 = {key(r) for r in r2}
    inter = sorted(s1 & s2)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(key_fields)
        w.writerows(inter)
    print(f"wrote {out} rows={len(inter)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

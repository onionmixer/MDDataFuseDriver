#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import csv

# Conservatively inferred from descriptor index order + parser token order near :\\mdctl
TOKENS = ["ON", "OFF", "IS", "FLUSH", "?"]
ROWS = [
    {"op_code": "0x0209", "op_index": "0", "handler_mdcache": "0x0818", "handler_mdformat": "0x135a"},
    {"op_code": "0x020a", "op_index": "1", "handler_mdcache": "0x082c", "handler_mdformat": "0x136e"},
    {"op_code": "0x0202", "op_index": "2", "handler_mdcache": "0x0840", "handler_mdformat": "0x1382"},
    {"op_code": "0x0243", "op_index": "3", "handler_mdcache": "0x0854", "handler_mdformat": "0x1396"},
    {"op_code": "0x0242", "op_index": "4", "handler_mdcache": "0x0868", "handler_mdformat": "0x13aa"},
]


def main() -> None:
    out = []
    for i, r in enumerate(ROWS):
        out.append(
            {
                "token_candidate": TOKENS[i],
                "op_code": r["op_code"],
                "op_index": r["op_index"],
                "handler_mdcache": r["handler_mdcache"],
                "handler_mdformat": r["handler_mdformat"],
                "evidence": "descriptor order + token order near :\\\\mdctl",
                "confidence": "inferred-low",
                "notes": "order-correlation only; runtime proof pending",
            }
        )

    md = [
        "# WS33 MDCTL Opcode Crosswalk",
        "",
        "Date: 2026-02-17",
        "",
        "| token_candidate | op_code | op_index | handler_mdcache | handler_mdformat | confidence | notes |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in out:
        md.append(
            f"| {r['token_candidate']} | {r['op_code']} | {r['op_index']} | {r['handler_mdcache']} | "
            f"{r['handler_mdformat']} | {r['confidence']} | {r['notes']} |"
        )

    md.extend(
        [
            "",
            "## Basis",
            "- Descriptor tuples are stable across `mdcache` and `mdformat` (`WS9`).",
            "- Token blob near `:\\mdctl` shows ordered command labels (`ON/OFF/IS/FLUSH/?`).",
            "- Exact dispatch linkage at instruction level is not yet proven.",
        ]
    )

    Path("analysis/ws33_mdctl_opcode_crosswalk.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    with open("analysis/ws33_mdctl_opcode_crosswalk.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "token_candidate",
                "op_code",
                "op_index",
                "handler_mdcache",
                "handler_mdformat",
                "evidence",
                "confidence",
                "notes",
            ],
        )
        w.writeheader()
        w.writerows(out)

    print("wrote analysis/ws33_mdctl_opcode_crosswalk.md and .csv")


if __name__ == "__main__":
    main()

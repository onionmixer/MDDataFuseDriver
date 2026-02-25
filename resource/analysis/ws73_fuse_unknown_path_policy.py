#!/usr/bin/env python3
from __future__ import annotations

import csv
from pathlib import Path


def main() -> None:
    rows = [
        {
            "scenario": "frame_len < 2",
            "route": "header guard",
            "errno": "EIO",
            "policy": "fail_closed_eio (forced)",
            "reason": "frame_too_short_for_req1",
            "status": "implemented",
        },
        {
            "scenario": "req1 != 9",
            "route": "unknown-path classifier",
            "errno": "EIO or ENOTSUP",
            "policy": "configurable (FailClosedEio / FeatureEnotsup)",
            "reason": "req1_not_in_supported_subset",
            "status": "implemented",
        },
        {
            "scenario": "req1 == 9 but frame truncated",
            "route": "case9 parser",
            "errno": "EIO",
            "policy": "fail_closed_eio (forced)",
            "reason": "case9_too_short",
            "status": "implemented",
        },
        {
            "scenario": "req1 == 9 and parse ok",
            "route": "case9 parser",
            "errno": "none",
            "policy": "n/a",
            "reason": "parsed_case9",
            "status": "implemented",
        },
    ]

    md = [
        "# WS73 FUSE Unknown-Path Error Policy",
        "",
        "Date: 2026-02-17",
        "",
        "## Summary",
        "- `mdfs-fuse` now defines explicit unknown-path handling with two modes:",
        "  fail-closed (`EIO`) and feature-gated unsupported (`ENOTSUP`).",
        "- Safety guards are strict: undersized request frames and case-9 parse truncation",
        "  are always rejected as `EIO` regardless of runtime mode.",
        "- Logging format is stabilized as single-line key/value records:",
        "  `level=WARN event=unknown_path req1=... req_len=... policy=... errno=... reason=...`.",
        "",
        "## Policy Matrix",
    ]
    for r in rows:
        md.append(
            f"- `{r['scenario']}` -> route `{r['route']}`, errno `{r['errno']}`, "
            f"policy `{r['policy']}`, reason `{r['reason']}` ({r['status']})"
        )

    md.extend(
        [
            "",
            "## Implementation Anchor",
            "- `mdfs-fuse-rs/crates/mdfs-fuse/src/lib.rs`",
            "- Key symbols: `UnknownPathPolicy`, `FuseErrno`, `UnknownPathEvent`, `route_request()`.",
        ]
    )

    Path("analysis/ws73_fuse_unknown_path_policy.md").write_text(
        "\n".join(md) + "\n", encoding="utf-8"
    )

    with Path("analysis/ws73_fuse_unknown_path_policy.csv").open(
        "w", newline="", encoding="utf-8"
    ) as f:
        w = csv.DictWriter(
            f,
            fieldnames=["scenario", "route", "errno", "policy", "reason", "status"],
        )
        w.writeheader()
        w.writerows(rows)

    print("wrote analysis/ws73_fuse_unknown_path_policy.md and .csv")


if __name__ == "__main__":
    main()

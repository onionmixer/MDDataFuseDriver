#!/usr/bin/env python3
from __future__ import annotations

import csv
from pathlib import Path


def main() -> None:
    rows = [
        {
            "area": "Driver identity parity (US/JP)",
            "need_for_fuse_ro": "required",
            "win31_evidence": "N/A (locale split is win95 package concern)",
            "win95_evidence": "core VxD triplet hashes identical US/JP",
            "status": "closed",
            "risk_if_missing": "high",
            "blocker_for_ro": "no",
            "anchors": "analysis/revalidate_all.py; document/MDFS_REVALIDATION_REPORT.md",
        },
        {
            "area": "Case selector stability (req[+1])",
            "need_for_fuse_ro": "required",
            "win31_evidence": "mdcache/mdformat descriptor tables give stable 5-op tuple",
            "win95_evidence": "mdmgr second dispatch narrowed; practical in-image subset req1=9",
            "status": "partial",
            "risk_if_missing": "high",
            "blocker_for_ro": "no",
            "anchors": "analysis/ws9_mdctl_dual_table.md; analysis/ws66_mdmgr_req1_domain_plausibility.md; analysis/ws70_mdmgr_case9_subtype_profile.md",
        },
        {
            "area": "Case-9 payload mapping",
            "need_for_fuse_ro": "required",
            "win31_evidence": "shared callback ABI pattern in mdfsck/mdfsex supports request/response lane model",
            "win95_evidence": "0x1047 tagged payload mapping + status split",
            "status": "closed_for_scaffold",
            "risk_if_missing": "high",
            "blocker_for_ro": "no",
            "anchors": "analysis/ws44_cross_binary_callback_abi.md; analysis/ws67_mdmgr_case9_1047_semantics.md; analysis/ws68_mdmgr_case9_status_output_flow.md",
        },
        {
            "area": "Unknown-path/error policy",
            "need_for_fuse_ro": "required",
            "win31_evidence": "legacy tools expose mixed command/error surface; not sufficient alone",
            "win95_evidence": "driver dispatch bounded but non-selected lanes unresolved",
            "status": "closed",
            "risk_if_missing": "high",
            "blocker_for_ro": "no",
            "anchors": "analysis/ws73_fuse_unknown_path_policy.md; mdfs-fuse-rs/crates/mdfs-fuse/src/lib.rs",
        },
        {
            "area": "On-media byte offsets (VD/VSB/MTB/ERB/DRB)",
            "need_for_fuse_ro": "required_for_real_mount",
            "win31_evidence": "field vocabulary and print lanes recovered but media offsets unresolved",
            "win95_evidence": "no direct byte-accurate offset closure in VxD static corpus",
            "status": "open",
            "risk_if_missing": "critical",
            "blocker_for_ro": "yes",
            "anchors": "analysis/ws23_layout_confirmed_table.csv; document/MDFS_SPEC_RFC.md",
        },
        {
            "area": "MDCTL opcode-to-payload schema",
            "need_for_fuse_ro": "optional_for_mount_ro",
            "win31_evidence": "opcode/token tuple inference available but low confidence",
            "win95_evidence": "private ioctl payload mapping unresolved",
            "status": "open",
            "risk_if_missing": "medium",
            "blocker_for_ro": "no",
            "anchors": "analysis/ws33_mdctl_opcode_crosswalk.md; analysis/ws6_mdctl_dataflow.md",
        },
        {
            "area": "LE type-3 flags (0x03) bit semantics",
            "need_for_fuse_ro": "optional",
            "win31_evidence": "N/A",
            "win95_evidence": "invariant and DDB-coupled, bit meaning unresolved",
            "status": "open",
            "risk_if_missing": "low",
            "blocker_for_ro": "no",
            "anchors": "analysis/ws27_le_type3_flags_survey.md; analysis/ws28_le_type3_flags_hypothesis.md",
        },
        {
            "area": "Runtime-loaded far pointer lanes (0x0c42 etc)",
            "need_for_fuse_ro": "optional_if_fail_closed",
            "win31_evidence": "callback ABI confirms dynamic lane concept",
            "win95_evidence": "single producer path known; loaded value unresolved",
            "status": "open_but_bounded",
            "risk_if_missing": "medium",
            "blocker_for_ro": "no",
            "anchors": "analysis/ws59_mdmgr_c42_load_chain_audit.md; analysis/ws58_mdmgr_dynamic_vector_prioritization.md",
        },
    ]

    md = [
        "# WS74 FUSE Data Gap Cross-Validation (Win31/Win95)",
        "",
        "Date: 2026-02-17",
        "",
        "## Goal",
        "- Re-check whether data is sufficient for Linux FUSE implementation by cross-validating",
        "  Win31 utilities and Win95 driver evidence.",
        "",
        "## Decision Summary",
        "- For conservative RO scaffold with fail-closed policy: data is sufficient to proceed.",
        "- For real media mount with normative parser: still blocked by unresolved on-media byte offsets.",
        "",
        "## Gap Matrix",
    ]

    for r in rows:
        md.append(
            f"- `{r['area']}` | need `{r['need_for_fuse_ro']}` | status `{r['status']}` | "
            f"blocker_for_ro `{r['blocker_for_ro']}` | anchors: {r['anchors']}"
        )

    md.extend(
        [
            "",
            "## Practical Interpretation",
            "1. `mdfs-fuse-rs` current 방향(WS73 fail-closed)은 타당하다.",
            "2. 다만 실제 이미지 파싱/마운트 기능을 켜려면 VD/VSB/MTB/ERB/DRB의",
            "   바이트 단위 오프셋 고정 근거가 추가로 필요하다.",
            "3. 따라서 다음 게이트는 런타임 미디어 트레이스 기반 오프셋 폐쇄다.",
        ]
    )

    Path("analysis/ws74_fuse_data_gap_cross_validation.md").write_text(
        "\n".join(md) + "\n", encoding="utf-8"
    )

    with Path("analysis/ws74_fuse_data_gap_cross_validation.csv").open(
        "w", newline="", encoding="utf-8"
    ) as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "area",
                "need_for_fuse_ro",
                "win31_evidence",
                "win95_evidence",
                "status",
                "risk_if_missing",
                "blocker_for_ro",
                "anchors",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print("wrote analysis/ws74_fuse_data_gap_cross_validation.md and .csv")


if __name__ == "__main__":
    main()

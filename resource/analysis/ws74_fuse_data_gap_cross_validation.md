# WS74 FUSE Data Gap Cross-Validation (Win31/Win95)

Date: 2026-02-17

## Goal
- Re-check whether data is sufficient for Linux FUSE implementation by cross-validating
  Win31 utilities and Win95 driver evidence.

## Decision Summary
- For conservative RO scaffold with fail-closed policy: data is sufficient to proceed.
- For real media mount with normative parser: still blocked by unresolved on-media byte offsets.

## Gap Matrix
- `Driver identity parity (US/JP)` | need `required` | status `closed` | blocker_for_ro `no` | anchors: analysis/revalidate_all.py; document/MDFS_REVALIDATION_REPORT.md
- `Case selector stability (req[+1])` | need `required` | status `partial` | blocker_for_ro `no` | anchors: analysis/ws9_mdctl_dual_table.md; analysis/ws66_mdmgr_req1_domain_plausibility.md; analysis/ws70_mdmgr_case9_subtype_profile.md
- `Case-9 payload mapping` | need `required` | status `closed_for_scaffold` | blocker_for_ro `no` | anchors: analysis/ws44_cross_binary_callback_abi.md; analysis/ws67_mdmgr_case9_1047_semantics.md; analysis/ws68_mdmgr_case9_status_output_flow.md
- `Unknown-path/error policy` | need `required` | status `closed` | blocker_for_ro `no` | anchors: analysis/ws73_fuse_unknown_path_policy.md; mdfs-fuse-rs/crates/mdfs-fuse/src/lib.rs
- `On-media byte offsets (VD/VSB/MTB/ERB/DRB)` | need `required_for_real_mount` | status `open` | blocker_for_ro `yes` | anchors: analysis/ws23_layout_confirmed_table.csv; document/MDFS_SPEC_RFC.md
- `MDCTL opcode-to-payload schema` | need `optional_for_mount_ro` | status `open` | blocker_for_ro `no` | anchors: analysis/ws33_mdctl_opcode_crosswalk.md; analysis/ws6_mdctl_dataflow.md
- `LE type-3 flags (0x03) bit semantics` | need `optional` | status `open` | blocker_for_ro `no` | anchors: analysis/ws27_le_type3_flags_survey.md; analysis/ws28_le_type3_flags_hypothesis.md
- `Runtime-loaded far pointer lanes (0x0c42 etc)` | need `optional_if_fail_closed` | status `open_but_bounded` | blocker_for_ro `no` | anchors: analysis/ws59_mdmgr_c42_load_chain_audit.md; analysis/ws58_mdmgr_dynamic_vector_prioritization.md

## Practical Interpretation
1. `mdfs-fuse-rs` current 방향(WS73 fail-closed)은 타당하다.
2. 다만 실제 이미지 파싱/마운트 기능을 켜려면 VD/VSB/MTB/ERB/DRB의
   바이트 단위 오프셋 고정 근거가 추가로 필요하다.
3. 따라서 다음 게이트는 런타임 미디어 트레이스 기반 오프셋 폐쇄다.

# WS76 SPEC Non-Media Review

Date: 2026-02-17
Objective: identify what can be strengthened in SPEC without MD DATA media, while enforcing no-estimate promotion.

## 1) Review Rule
- `INFERRED -> CONFIRMED` promotion requires direct evidence.
- No-media runtime repetition can strengthen stability statements only.
- Media-dependent items remain `UNKNOWN` until MD DATA-backed test evidence exists.

## 2) What Was Strengthened Without Media
- WS25 no-media runtime matrix:
  - scenarios: `mdcache is/on/off/flush`, `mdfsck d:`, `mdformat d: -q -o`
  - 2 runs per scenario, per-scenario intersections computed
  - cross-scenario common stable signature set (`10` rows) extracted
- Transport-lane repeatability claim is now backed by explicit run artifacts and summary tables.

## 3) What Must Stay UNKNOWN (Media Required)
- Byte-accurate on-media offsets for `VD/VSB/MTB/ERB/DRB`
- Full MD manager/control payload semantics
- Final semantic meaning of LE `type=3` flags `0x03`

## 4) Spec Updates Applied
- Added promotion-gate policy in `document/MDFS_SPEC_FINAL.md`.
- Added no-media reinforcement subsection in `document/MDFS_SPEC_FINAL.md`.
- Added explicit closure requirements and no-estimate restriction for known gaps.
- Added no-media run artifacts to evidence index.
- Added matching caution text in `document/MDFS_EVIDENCE_GAP_AUDIT.md`.

## 5) Deferred to Test Stage
- MD DATA media-backed differential traces for payload semantics and byte offsets.
- Contrasting media-state runs for candidate field promotion.

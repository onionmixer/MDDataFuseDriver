# WS77 SPEC Promotion Checklist (Non-Media -> Media Stage)

Date: 2026-02-17
Purpose: keep estimated/candidate findings out of normative SPEC until test-stage closure criteria are met.

## Rule
- Do not promote `INFERRED` to `CONFIRMED` without direct evidence.
- No-media repeatability is supporting evidence only.
- Media-dependent items require MD DATA media-backed trace/diff evidence.

## Promotion Candidates (Current)
Source files:
- `analysis/ws26_mdctl_schema_matrix.csv`
- `analysis/ws26_nomedia_promotion_candidates.csv`

### A. No-media repeatable transport lanes
- Status: `INFERRED` (repeatable)
- Evidence:
  - `analysis/ws25_nomedia/summary.csv`
  - `analysis/ws25_nomedia/common_all_scenarios.csv`
- Promotion requirement:
  - reproduce under MD DATA media with contrasting scenarios
  - show stability while command semantics diverge meaningfully by scenario

### B. MDCTL payload semantics
- Status: `UNKNOWN`
- Evidence now:
  - static anchors + no-media runtime lanes
- Promotion requirement:
  - request/response payload capture on real MD DATA media
  - field-level mapping repeatable across >=2 runs and >=1 contrasting scenario

### C. On-media byte offsets (VD/VSB/MTB/ERB/DRB)
- Status: `UNKNOWN`
- Promotion requirement:
  - before/after media images + parser-aligned byte offset proof
  - consistency against checker/formatter observed outputs

### D. LE type-3 flags `0x03` semantics
- Status: `UNKNOWN`
- Promotion requirement:
  - independent semantic binding (broader corpus and/or runtime behavior linkage)

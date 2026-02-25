# WS28 LE Type-3 Flags Hypothesis

Date: 2026-02-17

## Input Evidence
- `analysis/ws10_le_type3_middleword.md`
- `analysis/ws27_le_type3_flags_survey.md`
- `analysis/ws2_le_entry_x86.md`
- `analysis/ws2_vxd_ddb_candidates.md`

## Confirmed Facts
- In this corpus, type-3 entry records are only observed at ordinal 1.
- All observed type-3 entries have `flags=0x03`.
- The same records map to DDB offsets (`middle16`) and nonresident export names (`_The_DDB` / `MDHlp_DDB`).
- US/JP binaries are identical for the 3 target VxDs, so no additional flag variance exists in current samples.

## Bounded Hypotheses
1. DDB-export marker hypothesis `[INFERRED]`
- `flags=0x03` is a loader/export qualifier used with DDB-style type-3 exports.
- Support: value is invariant across all observed DDB exports and absent from non-type-3 entries.

2. Generic type-3 mandatory flags hypothesis `[INFERRED]`
- `0x03` may be fixed-required bits for type-3 x86 entries irrespective of module role.
- Support: no counterexample in current corpus.
- Limitation: corpus contains only 3 unique VxDs.

3. Bitfield-semantics unresolved hypothesis `[UNKNOWN]`
- Exact per-bit meaning (e.g., calling/data/privilege semantics) is not recoverable from current static evidence alone.

## Reduction Achieved
- UNKNOWN is reduced from "completely unknown flags meaning" to:
  - "`0x03` is strongly tied to type-3 DDB export entries in this corpus"
  - "bit-level semantics remain unresolved"

## Required Next Proof
- Runtime loader probe (`WS29`) with controlled flag-byte mutation in disposable copy:
  - baseline `0x03`
  - trial `0x01`, `0x02`, `0x00`, `0x07`
- Observe Win95 loader behavior and DDB registration outcome.

# WS21 Layout Candidate Map

Date: 2026-02-17

Source: `analysis/ws19_mdfsck_vd_emit_map.csv`.

| field_label | printf_spec | value_class | value_words | candidate_globals | call_mem | confidence |
| --- | --- | --- | --- | --- | --- | --- |
| Identifier | %s | str | 1 |  | 0x0673 | inferred |
| Version | %d | u16 | 1 |  | 0x0685 | inferred |
| BlockSize | %d | u16 | 1 | 0x5b40 | 0x0695 | inferred |
| ClusterSize | %d | u16 | 1 | 0x5b42 | 0x06a5 | inferred |
| AllocSize | %d | u16 | 1 | 0x5b44 | 0x06b5 | inferred |
| NumAlloc | %ld | u32 | 2 | 0x5b4a,0x5b48 | 0x06c9 | inferred |
| NumRecordable | %ld | u32 | 2 | 0x5b4e,0x5b4c | 0x06dd | inferred |
| NumAvaiable [sic] | %ld | u32 | 2 | 0x5b52,0x5b50 | 0x06f1 | inferred |
| NumUsed | %ld | u32 | 2 | 0x5b56,0x5b54 | 0x0705 | inferred |
| NumDefective | %d | u16 | 1 | 0x5b58 | 0x0719 | inferred |
| NumDir | %d | u16 | 1 | 0x5b60 | 0x0729 | inferred |
| NumFile | %d | u16 | 1 | 0x5b62 | 0x0739 | inferred |
| MaxIdNum | %d | u16 | 1 | 0x5b64 | 0x074d | inferred |
| VolAttr | %04x | u16 | 1 | 0x5b68 | 0x075d | inferred |
| VMALen | %ld | u32 | 2 | 0x5b6e,0x5b6c | 0x077c | inferred |
| VMALoc | %ld | u32 | 2 | 0x5b72,0x5b70 | 0x0790 | inferred |
| VSBLoc | %d | u16 | 1 | 0x5b74 | 0x07a0 | inferred |
| VSBNum | %d | u16 | 1 | 0x5b76 | 0x07b0 | inferred |
| MTBLoc | %d | u16 | 1 | 0x5b78 | 0x07c0 | inferred |
| MTBNum | %d | u16 | 1 | 0x5b7a | 0x07d0 | inferred |
| ERBLoc | %d | u16 | 1 | 0x5b7c | 0x07e0 | inferred |
| ERBNum | %d | u16 | 1 | 0x5b7e | 0x07f0 | inferred |
| DRBLoc | %d | u16 | 1 | 0x5b80 | 0x0800 | inferred |
| DRBNum | %d | u16 | 1 | 0x5b82 | 0x0810 | inferred |
| DirLen | %ld | u32 | 2 | 0x5b86,0x5b84 | 0x0824 | inferred |
| NumChild | %d | u16 | 1 | 0x5b88 | 0x0834 | inferred |

## Notes
- `candidate_globals` uses trailing argument words by format-width heuristic.
- This map identifies checker variable lanes, not byte-accurate media offsets.
- `NumAvaiable` is a typo in the original `mdfsck.exe` binary string (should be `NumAvailable`); preserved faithfully with `[sic]`.

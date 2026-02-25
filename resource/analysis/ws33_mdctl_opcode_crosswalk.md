# WS33 MDCTL Opcode Crosswalk

Date: 2026-02-17

| token_candidate | op_code | op_index | handler_mdcache | handler_mdformat | confidence | notes |
| --- | --- | --- | --- | --- | --- | --- |
| ON | 0x0209 | 0 | 0x0818 | 0x135a | inferred-low | order-correlation only; runtime proof pending |
| OFF | 0x020a | 1 | 0x082c | 0x136e | inferred-low | order-correlation only; runtime proof pending |
| IS | 0x0202 | 2 | 0x0840 | 0x1382 | inferred-low | order-correlation only; runtime proof pending |
| FLUSH | 0x0243 | 3 | 0x0854 | 0x1396 | inferred-low | order-correlation only; runtime proof pending |
| ? | 0x0242 | 4 | 0x0868 | 0x13aa | inferred-low | order-correlation only; runtime proof pending |

## Basis
- Descriptor tuples are stable across `mdcache` and `mdformat` (`WS9`).
- Token blob near `:\mdctl` shows ordered command labels (`ON/OFF/IS/FLUSH/?`).
- Exact dispatch linkage at instruction level is not yet proven.

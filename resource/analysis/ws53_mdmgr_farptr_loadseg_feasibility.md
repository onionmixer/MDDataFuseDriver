# WS53 mdmgr Far-pointer Load-segment Feasibility

Date: 2026-02-17

- image length: `0x3252`

## Per-pointer feasible load-segment ranges
| name | segment | offset | feasible S min | feasible S max | count |
| --- | --- | --- | --- | --- | --- |
| entry0_init | 0x478a | 0x2606 | 0x46c6 | 0x49ea | 805 |
| entry1_init | 0x6b00 | 0xb402 | 0x731c | 0x7640 | 805 |
| entry1_set | 0x011f | 0x095c | 0x0000 | 0x01b4 | 437 |
| entry2_init | 0x2e05 | 0x14c0 | 0x2c2c | 0x2f51 | 806 |

## Intersection checks
- entry0_init ∩ entry2_init: none
- entry0_init ∩ entry1_set: none
- entry2_init ∩ entry1_set: none

## Conclusion
- `entry0_init` and `entry2_init` cannot be mapped in-image under a single common load segment with `entry1_set`.
- This strengthens that #0/#2 initial pointers are not same-module in-image handlers under the observed model.
- Combined with WS52, #0/#2 are high-confidence external/resident targets; #1 is rewritten to local in-image handler.

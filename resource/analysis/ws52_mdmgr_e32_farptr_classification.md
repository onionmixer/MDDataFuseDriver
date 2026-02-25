# WS52 mdmgr 0x0e32 Far-pointer Classification

Date: 2026-02-17

- image length (post-MZ-header): `0x3252`

## Initial Entry Values (`offset:segment`)
| entry | low | high | offset | segment | linear | in_image |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | 0x0e32 | 0x0e34 | 0x2606 | 0x478a | 0x49ea6 | no |
| 1 | 0x0e36 | 0x0e38 | 0xb402 | 0x6b00 | 0x76402 | no |
| 2 | 0x0e3a | 0x0e3c | 0x14c0 | 0x2e05 | 0x2f510 | no |

## Entry #1 Re-init (from WS48 writes)
- code writes: `[0x0e36]=0x095c`, `[0x0e38]=0x011f`
- interpreted far pointer: `011f:095c` (linear `0x01b4c`)
- in-image after re-init: yes

## Conclusion
- Dispatch entries are true far pointers (`lcall m16:16`), not near offsets.
- Initial entry #0 and #2 point outside current image address space, consistent with external/resident target stubs.
- Entry #1 is rewritten to an in-image handler pointer by code, matching observed explicit writes.

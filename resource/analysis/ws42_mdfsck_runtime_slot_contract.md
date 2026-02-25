# WS42 mdfsck Runtime Slot Contract (0x1960..0x1976)

Date: 2026-02-17

## Segment Bases
- `CS=0x03f7` => `CS_base=0x3f70`
- `DS=0x0dcd` => `DS_base=0xdcd0`

## Slot Summary
| slot | init_u16 | refs | reads | writes | indirect |
| --- | --- | --- | --- | --- | --- |
| 0x1960 | 0x00f2 | 3 | 0 | 0 | 3 |
| 0x1962 | 0x00f2 | 1 | 0 | 0 | 1 |
| 0x1964 | 0x00f2 | 1 | 0 | 0 | 1 |
| 0x1966 | 0x0000 | 0 | 0 | 0 | 0 |
| 0x1968 | 0x0000 | 0 | 0 | 0 | 0 |
| 0x196a | 0x0000 | 0 | 0 | 0 | 0 |
| 0x196c | 0x0000 | 3 | 0 | 0 | 3 |
| 0x196e | 0x0000 | 2 | 2 | 0 | 0 |
| 0x1970 | 0x0000 | 1 | 1 | 0 | 0 |
| 0x1972 | 0x0000 | 1 | 1 | 0 | 0 |
| 0x1974 | 0x0000 | 1 | 1 | 0 | 0 |
| 0x1976 | 0x0000 | 1 | 1 | 0 | 0 |

## Key Findings
- `0x1960/0x1962/0x1964` are near-call vector words with image-init value `0x00f2` and no static writes.
- `0x196c` is a far-call vector low word used at three `lcall [0x196c]` sites; image-init value is `0x0000` and static writes are not present.
- `0x196e` gates the `0x196c` call path (`jcxz` checks) and is also image-init `0x0000` with no static writes.
- `0x1970..0x1976` feed AX:DX arguments into `lcall [0x196c]`; all are image-init zero with read-only static usage.
- Combined evidence supports a runtime-populated callback/continuation contract for the `0x196c..0x1976` slot family.

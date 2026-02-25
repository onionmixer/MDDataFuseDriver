# WS20 mdfsck Cluster Xrefs

Date: 2026-02-17

Target cluster: `0x3994..0x3f4a`.

## Incoming call xrefs

| caller | mnemonic | target | op_str |
| --- | --- | --- | --- |
| 0x3975 | call | 0x3a24 | 0x3a24 |
| 0x3a33 | call | 0x3994 | 0x3994 |
| 0x3a47 | call | 0x3994 | 0x3994 |
| 0x3e0d | call | 0x3cca | 0x3cca |
| 0x3e2d | call | 0x3cca | 0x3cca |
| 0x3e42 | call | 0x3a4c | 0x3a4c |
| 0x3e60 | call | 0x3adc | 0x3adc |

## Focus helper callsites

| helper | callers |
| --- | --- |
| 0x3a4c | 0x3e42 |
| 0x3adc | 0x3e60 |
| 0x3cca | 0x3e0d,0x3e2d |
| 0x3df2 |  |
| 0x3e12 |  |
| 0x3e32 |  |
| 0x3e72 |  |
| 0x3ef0 |  |
| 0x3f4a |  |

## Notes
- This enumerates direct immediate call-style xrefs only.
- Indirect calls/jump tables/function pointers are not resolved in this pass.

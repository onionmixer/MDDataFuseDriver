# WS49 mdmgr 0x0e32 Relocation Crosscheck

Date: 2026-02-17

- MZ relocation entries: `111`
- Relocation table offset: `0x003e`
- Image base (header paragraphs): `0x0200`

## Dispatch Entry Relocation Status
| entry | low | high | init_low | init_high | low_reloc | high_reloc |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | 0x0e32 | 0x0e34 | 0x2606 | 0x478a | no | no |
| 1 | 0x0e36 | 0x0e38 | 0xb402 | 0x6b00 | no | no |
| 2 | 0x0e3a | 0x0e3c | 0x14c0 | 0x2e05 | no | no |

## Comparison Slots
| name | low | high | low_reloc | high_reloc |
| --- | --- | --- | --- | --- |
| c42_pair | 0x0c42 | 0x0c44 | no | no |
| cfa_pair | 0x0cfa | 0x0cfc | no | no |
| cfe_pair | 0x0cfe | 0x0d00 | no | no |

## Conclusion
- `0x0e32` table entry words are not relocation-marked in the MZ table.
- Combined with WS48 (entry #1 explicit write, #0/#2 no literal writes), entry #0/#2 remain unresolved static constants from current image view.
- This suggests provider closure for #0/#2 likely needs deeper runtime tracing or non-literal write path recovery, not simple MZ reloc explanation.

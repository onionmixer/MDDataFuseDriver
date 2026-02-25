# WS35 mdcache Relocation Sanity Check

Date: 2026-02-17

- reloc_count: `627`
- header_bytes: `0x1000`
- cluster_range(file): `0x0d000..0x0d140`

## Method A (standard MZ cell addressing)
- hits: `4`

| rel# | cell_file_off | target_file_off | far(seg:off) |
| --- | --- | --- | --- |
| 115 | 0x0d03c | 0x3bfca | 3a44:0b8a |
| 127 | 0x0d0b6 | 0x01000 | 0000:0000 |
| 128 | 0x0d0b2 | 0x04a90 | 03a9:0000 |
| 129 | 0x0d0ae | 0x04a90 | 03a9:0000 |

## Method B (legacy seg_fix-2 heuristic)
- hits: `4`

| rel# | cell_file_off | target_file_off | far(seg:off) |
| --- | --- | --- | --- |
| 115 | 0x0d03a | 0x0d052 | 0b8a:07b2 |
| 127 | 0x0d0b4 | 0x013a9 | 0000:03a9 |
| 128 | 0x0d0b0 | 0x013a9 | 0000:03a9 |
| 129 | 0x0d0ac | 0x013a9 | 0000:03a9 |

## Conclusion
- Relocation-to-blob evidence is method-sensitive in current scripts.
- Keep token/descriptor contiguity as primary evidence; treat relocation linkage as lower-confidence until runtime-backed.

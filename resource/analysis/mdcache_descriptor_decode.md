# mdcache Descriptor Decode (WS7)

Date: 2026-02-16

## 1) Callback Trio
- base: `0x0d0ac`
- cb0: `0x000003a9` (mem=0x013a9)
- cb1: `0x000003a9` (mem=0x013a9)
- cb2: `0x000003a9` (mem=0x013a9)

## 2) 5x Descriptor Records (`0x14` stride)
| idx | rec_off | d0 | d1 | d2 | d3 | d4(handler) | op_code | op_index | handler_mem | prologue_mem |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 0x0d0ba | 0x00000209 | 0x00000000 | 0x00000000 | 0x00000000 | 0x00000818 | 0x0209 | 0x0000 | 0x01818 | n/a |
| 2 | 0x0d0ce | 0x0001020a | 0x00000000 | 0x00000000 | 0x00000000 | 0x0000082c | 0x020a | 0x0001 | 0x0182c | n/a |
| 3 | 0x0d0e2 | 0x00020202 | 0x00000000 | 0x00000000 | 0x00000000 | 0x00000840 | 0x0202 | 0x0002 | 0x01840 | 0x01835 |
| 4 | 0x0d0f6 | 0x00030243 | 0x00000000 | 0x00000000 | 0x00000000 | 0x00000854 | 0x0243 | 0x0003 | 0x01854 | 0x01835 |
| 5 | 0x0d10a | 0x00040242 | 0x00000000 | 0x00000000 | 0x00000000 | 0x00000868 | 0x0242 | 0x0004 | 0x01868 | 0x0185a |

## 3) Token Order Near `:\\mdctl`
- token_1: `ON`
- token_2: `ERROR:`
- token_3: `OFF`
- token_4: `ERROR:`
- token_5: `IS`
- token_6: `ERROR:`
- token_7: `FLUSH`
- token_8: `ERROR:`
- token_9: `?`

## 4) Conservative Interpretation
- Descriptor block shape is highly regular (3 callbacks + 5 records).
- Record `d4` low-word values map to valid code-region addresses.
- Record `d0` low/high words look like `(op_code, op_index)` pairs.
- Observed pairs: `(0209,0)`, `(020a,1)`, `(0202,2)`, `(0243,3)`, `(0242,4)`.
- Token order near the same blob is `ON/OFF/IS/FLUSH/?`.
- Therefore command-table linkage is strongly suggested but still not fully proven at instruction-level dispatch.

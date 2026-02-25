# WS34 mdcache Blob/Descriptor Cluster

Date: 2026-02-17

## Layout (file offsets)
- token blob start: `0x0d052`
- descriptor base: `0x0d0ac`
- first record: `0x0d0ba` (`count=5`, `stride=0x14`)

## Token order in cluster
- :\mdctl -> ON -> ERROR: -> OFF -> ERROR: -> IS -> ERROR: -> FLUSH -> ERROR: -> ?

## Descriptor tuples

| rec_idx | rec_off | op_code | op_index | handler16 |
| --- | --- | --- | --- | --- |
| 0 | 0x0d0ba | 0x0209 | 0 | 0x0818 |
| 1 | 0x0d0ce | 0x020a | 1 | 0x082c |
| 2 | 0x0d0e2 | 0x0202 | 2 | 0x0840 |
| 3 | 0x0d0f6 | 0x0243 | 3 | 0x0854 |
| 4 | 0x0d10a | 0x0242 | 4 | 0x0868 |

## Relocation hits into cluster region

| rel# | ptr_cell_file_off | target_file_off | target_seg | target_off |
| --- | --- | --- | --- | --- |

## Interpretation
- Token strings and 5-record descriptor table are contiguous in one data cluster.
- Descriptor order and token order are structurally compatible, but instruction-level dispatch proof is still pending.
- This supports WS33 as bounded low-confidence crosswalk evidence.

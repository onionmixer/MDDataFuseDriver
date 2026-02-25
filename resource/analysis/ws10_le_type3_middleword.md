# LE Type-3 Middle Word Validation (WS10)

Date: 2026-02-17

| file | obj | flags | middle16 | data_pages | ddb_off | ddb[+0] | ddb[+4] | ddb[+8] | ddb[+0xc..] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| w95/extract/us/mdmgr.vxd | 1 | 0x03 | 0x0320 | 0x1000 | 0x1320 | 0x00000000 | 0x00000400 | 0x00000001 | `MDMGR   ` |
| w95/extract/us/mdhlp.vxd | 1 | 0x03 | 0x02bc | 0x1000 | 0x12bc | 0x00000000 | 0x00000400 | 0x00000004 | `MDHlp   ` |
| w95/extract/us/mdfsd.vxd | 1 | 0x03 | 0x5200 | 0x1000 | 0x6200 | 0x00000000 | 0x00000400 | 0x00000001 | `MDFSD   ` |

## Conclusion
- For all 3 VxDs, type-3 entry middle16 points to a valid DDB-like structure.
- The resolved structure shares stable fields (`+0x00=0`, `+0x04=0x00000400`, module name at `+0x0c`).
- Therefore middle16 is best interpreted as an object-relative DDB offset (not a code entry RVA).
- `flags=0x03` semantic meaning remains partially unknown, but this dataset ties middle16 to DDB location.

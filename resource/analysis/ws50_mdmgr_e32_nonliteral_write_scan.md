# WS50 mdmgr 0x0e32 Non-literal Write Scan

Date: 2026-02-17

- target range: `0x0e32..0x0e3c`
- direct absolute writes in range: `2`
- reg+disp resolved write candidates in range: `0`
- block-copy candidates with `DI` in range: `0`

## Direct writes
- `0x19d5: mov word ptr [0xe38], 0x11f` -> `0x0e38`
- `0x19db: mov word ptr [0xe36], 0x95c` -> `0x0e36`

## Conclusion
- No additional non-literal write path into `0x0e32..0x0e3c` was confirmed by this bounded static scan.
- Remaining provider uncertainty for entry #0/#2 persists as runtime/non-obvious dataflow issue.

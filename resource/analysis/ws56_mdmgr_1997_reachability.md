# WS56 mdmgr 0x1997 Reachability Audit

Date: 2026-02-17

Scope: `w31/extract/mdmgr.exe` block `0x1997..0x1a3f` (contains writes `0x19d5/0x19db` to `0x0e38/0x0e36`).

## Primary Results
- Capstone direct branch/call references to `0x1997`: 0
- External inbound references into `0x1997..0x1a3f`: 0
- Raw opcode-pattern hits targeting `0x1997`: 0
- Interpretation: this block is statically isolated in current image-level evidence.

## Dispatcher Window (`0x1c60..0x1cb1`) Direct Calls
- `0x1c66: call 0x1511`
- `0x1c72: call 0x165e`
- `0x1c7e: call 0x1771`
- `0x1c8a: call 0x1868`
- `0x1c96: call 0x193b`
- `0x1ca2: call 0x1969`
- `0x1cae: call 0x12ca`

## Notes
- The dispatcher shows direct cases to `0x1511/0x165e/0x1771/0x1868/0x193b/0x1969/0x12ca` and then returns to common tail.
- No direct case to `0x1997` is present in this window.
- MZ `e_ovno` is `0` (`0` in this sample), so classic EXE overlay indicator is not set.
- This does not prove runtime impossibility (e.g., overlay/loader mutation), but no static in-image transfer is observed.

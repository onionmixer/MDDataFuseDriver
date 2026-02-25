# WS64 mdmgr req[+1] Provenance Partition

Date: 2026-02-17

## Findings
- total `es:[bx+1]` touch points: 14
- in handler window `0x0d31..0x0ef6`: reads=3, writes=0
- handler touch points are read-only (`0x0d67`, `0x0d74`, `0x0e49`), supporting interpretation that `req[+1]` is input in this function.
- guard-derived second-dispatch domain remains `req[+1] in [9, 10, 11, 12, 13]`.
- writes to `es:[bx+1]` are observed outside this handler (builder/formatter-style paths), and are not directly shown to dominate `0x0d31` input.
- Conclusion: for second-dispatch analysis, `req[+1]` should be treated as externally supplied contract field at `0x0d31` entry.

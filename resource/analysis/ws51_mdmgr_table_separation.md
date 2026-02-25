# WS51 mdmgr Table Separation (`0x0e32` vs `0x0e84` family)

Date: 2026-02-17

- dispatch table window: `0x0e32..0x0e3f`
- device table window: `0x0e7e..0x0e8f`
- dispatch function window: `0x1ccc..0x1d28`
- init function window: `0x19fe..0x1a35`

## Aggregates
- dispatch-table refs inside dispatch function: `3`
- device-table refs inside dispatch function: `0`
- device-table refs inside init function: `3`
- dispatch-table refs inside init function: `0`

## Key observations
- Dispatch function (`0x1ccc..`) uses `[bx+0xe32]/[bx+0xe34]` indexed far-call path.
- Init function (`0x19fe..`) sets device table entries (`0xe7e`, `0xe84`, `0xe86`) and does not write `0x0e32` base entry words.
- This supports that `0xe84/0xe86` table is separate per-device metadata, not provider source for `0xe32` entry #0/#2.

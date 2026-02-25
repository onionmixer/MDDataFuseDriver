# WS63 mdmgr Second-dispatch Target Materialization

Date: 2026-02-17

Scope: jump table at `cs:[bx+0x07df]` used by `0x0e58`.

## Findings
- table entries analyzed: 14
- direct static writes to `0x07df..0x07f9`: 0
- relocation hits on table words: 0
- second-dispatch domain from guards: `req[+1] in {9,10,11,12,13}`.
- within that domain, targets inside current image: 2/5.
- Interpretation: table is not statically materialized by observed writes/relocs; behavior depends on protocol-level reachable opcode subset in `req[+1]`.

## Domain Entries (`req[+1]=9..13`)
- idx 9: target 0x1047 (in_image=yes)
- idx 10: target 0x00b4 (in_image=yes)
- idx 11: target 0xc06b (in_image=no)
- idx 12: target 0x8b11 (in_image=no)
- idx 13: target 0xffd8 (in_image=no)

# WS67 mdmgr req[+1]=9 Path (`0x1047`) Semantics

Date: 2026-02-17

Scope: second-dispatch plausible target `0x1047` from `req[+1]=9` (`0x0e58` table).

## Structural Behavior
- Branch key: `req[0x17]` (`cmp byte ptr es:[bx+0x17],0`).
- If zero branch (`0x104f` fallthrough): output tag `out[0]=0x45` and scatter copy from `req[0x10..0x14]` into `out[5],out[4],out[3],out[2],out[8]`; `out[7]=req[0x15]`.
- If non-zero branch (`0x10a7`): output tag `out[0]=0x48`; `out[4]=req[0x10]`; `out[7]=req[0x10]+req[0x14]`.
- No status-byte write (`req+3`) occurs inside `0x1047`; status handling remains in outer caller path.

## Inference
- `req[+1]=9` likely selects a formatter-like subcommand with two record layouts (`0x45` vs `0x48`) keyed by `req[0x17]`.
- This strengthens practical-subset interpretation from WS66: case `9` is not only jump-plausible but semantically coherent as a structured output builder.

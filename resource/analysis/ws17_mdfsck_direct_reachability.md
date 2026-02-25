# WS17 mdfsck Direct Reachability Check

Date: 2026-02-17

## Method
- Entry point: MZ `CS:IP` converted to memory offset (`0x3f8e`).
- Traversal: linear decode with near `call/jcc/jmp` target following.
- Out of scope: indirect calls/jumps (`call [..]`, callback tables), far-segment transfer semantics.

## Result
- Directly reached instruction addresses: `312`.
- The following frame/transport helper cluster addresses were **not** reached in direct near-call CFG:
  - `0x3994`
  - `0x3a4c`
  - `0x3adc`
  - `0x3cca`
  - `0x3df2`
  - `0x3e12`
  - `0x3e32`
  - `0x3e72`
  - `0x3ef0`
  - `0x3f4a`

## Interpretation (Conservative)
- Current payload-shape findings for this cluster remain valid as static code-structure evidence.
- However, based on direct near-call CFG from process entry alone, this cluster appears to be:
  - an alternate execution path,
  - callback/indirect dispatch target, or
  - linked helper code not always exercised by default path.
- Therefore behavior statements for these routines should stay at `[INFERRED]` unless dynamic trace confirms runtime activation.

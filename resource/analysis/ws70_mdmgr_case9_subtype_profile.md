# WS70 mdmgr Case-9 Provisional Subtype Profile

Date: 2026-02-17

## Profile Summary
- Provisional subtype anchor: second-dispatch practical subset converges to `req[+1]=9`.
- Control-flow, payload-shape, status ownership, and input-lane provenance are now mutually consistent in static evidence.
- Recommended spec stance: treat case-9 as a stable provisional subtype profile while keeping semantic names/opcode label as `[UNKNOWN]`.

## Consolidated Dimensions
- `dispatch_domain`: req[+1] in 9..13 (guarded) (`high`, WS63)
- `practical_subset`: req[+1]=9 (0x1047) only plausible in-image target (`high`, WS66)
- `entry_semantics`: 0x1047 tagged formatter path (0x45/0x48 by req[0x17]) (`high`, WS67)
- `status_ownership`: handler sets req+3 status; 0x1047 does not overwrite status (`high`, WS68)
- `input_provenance`: req[0x10..0x17] read-mostly pre-assembled contract lanes (`medium-high`, WS69)
- `remaining_unknown`: exact external producer/semantic names of req fields and subtype label (`open`, WS64-WS69)

## Unknown Priority Reorder (Case-9 scope)
1. External producer path that assembles `req[0x10..0x17]` contract bytes.
2. Semantic naming/labeling of `req[+1]=9` subtype in MDCTL-level taxonomy.
3. Runtime confirmation of non-selected domain values (`10..13`) under real protocol traffic.

# WS31 mdfsck Runtime Trace

Date: 2026-02-17
Status: runtime trace playbook (prepared)

## Goal
Close remaining reachability uncertainty for helper cluster `0x3994..0x3f4a` by tracing unresolved runtime vectors.

## Static Baseline
- From `WS20`: direct immediate xrefs into cluster are intra-cluster only.
- From `WS30`: resolved indirect sites do not enter cluster.
- Open vectors:
  - `lcall [0x196c]` at `0x40d1`, `0x40e4`, `0x41f9`
  - `lcall [di]` at `0x4217`
  - sentinel/null far slots: `[0x14d2]`, `[0x14d6]`, `[0x14dc]`, `[0x177a]`

## Required Runtime Captures
1. Capture effective far target for each unresolved site.
2. Capture whether execution reaches any of:
- `0x3994`, `0x3a24`, `0x3a4c`, `0x3adc`, `0x3cca`, `0x3e32`, `0x3e72`, `0x3ef0`, `0x3f4a`.
3. Capture call context at first hit:
- `CS:IP`, `DS`, `SS:SP`, key argument words around stack (`[SP..SP+0x20]`).

## Breakpoint Set
- unresolved vectors:
  - `0x40d1`, `0x40e4`, `0x41f9`, `0x4217`, `0x422e`, `0x4264`, `0x4430`, `0x5b51`
- cluster ingress points:
  - `0x3994`, `0x3a24`, `0x3a4c`, `0x3adc`, `0x3cca`, `0x3e32`, `0x3e72`, `0x3ef0`, `0x3f4a`

## Scenario Matrix
1. `mdfsck <drive>:` baseline check (`-v` off)
2. `mdfsck <drive>: -v`
3. media state variants:
- clean formatted
- intentionally mutated header/bitmap (if safely reproducible)

## Expected Decision Rules
- If any unresolved vector resolves into cluster target range, mark cluster reachability as runtime-confirmed.
- If vectors repeatedly resolve outside cluster across all scenarios, reduce cluster path likelihood and classify as conditional/dead for tested conditions.
- If only `-v` or mutated media triggers cluster, classify as diagnostic/error path.

## Output Format for WS32
- `helper_addr,path_class,evidence,confidence,notes`
- path_class in `{hot,conditional,diagnostic,unreached}`

## Notes
- Keep binary image immutable.
- Log raw trace with absolute linear addresses to avoid segment/offset ambiguity.

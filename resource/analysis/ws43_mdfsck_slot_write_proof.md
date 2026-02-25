# WS43 mdfsck Slot Write Proof (0x196c..0x1976)

Date: 2026-02-17

## Segment Bases
- `CS=0x03f7` (`CS_base=0x3f70`)
- `DS=0x0dcd` (`DS_base=0xdcd0`)

## Result Summary
- direct writes to `0x196c..0x1976`: 0
- heuristic indirect-write candidates to same range: 0

## Direct writes
- none found in linear-disassembly pass

## Indirect candidates
- none found by immediate-base backtrace heuristic

## Conclusion
- Static evidence continues to support that `0x196c..0x1976` are runtime-populated lanes.
- Full closure still requires runtime capture of slot initialization source.

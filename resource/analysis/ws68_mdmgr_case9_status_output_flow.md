# WS68 mdmgr Case-9 Status and Output Flow

Date: 2026-02-17

## Findings
- handler (`0x0d31..0x0ef6`) status writes (`req+3`): 4
- case9 target (`0x1047`) status writes (`req+3`): 0
- Handler pre-initializes status to zero at `0x0d5f` before second-dispatch checks.
- Case-9 path at `0x1047` writes output fields but does not write status byte.
- Case-9 function ends with `retf` (`0x10d2`), so control exits via far return after table jump path.
- Inference: for successful case-9 path, status remains the handler-initialized success value unless earlier guard/error branch fires.

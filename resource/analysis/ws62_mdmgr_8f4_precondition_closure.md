# WS62 mdmgr 0x08f4 Preconditions Closure

Date: 2026-02-17

## Findings
- direct caller count to `0x08f4`: 1
- only direct caller observed: `0x0e70` in `0x0d31` handler function.
- same function enforces `req[2] < 8` (`0x0e11`/`0x0e16`) before second-stage dispatch that includes `0x0e70`.
- therefore `k=req[+2]` used in `0x08f4 -> 0x0916` is bounded to `0..7` in this static path.
- closure verdict for prior `k>=8` concern: closed for observed direct-call path.
- residual uncertainty shifts away from `k` range and remains on runtime dispatch target/value materialization details.

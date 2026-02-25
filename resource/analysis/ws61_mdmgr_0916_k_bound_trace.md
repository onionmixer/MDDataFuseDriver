# WS61 mdmgr 0x0916 k-Bound Trace

Date: 2026-02-17

## Findings
- direct caller count to `0x08f4`: 1
- observed direct caller: `0x0e70`.
- caller-side explicit bound observed on `req[+1]` (`<=0x0d`) before jump-table dispatch.
- in `0x08f4`, `k` is loaded from `req[+2]`, transformed (`*0x14`), remapped via `[0x0d30 + ...]`, then used for lane dispatch at `0x0916`.
- explicit in-function bound check on `k` before `0x0916`: not observed.
- Conclusion: residual `k>=8` uncertainty is a caller-contract/runtime-data issue; no local static clamp is observed in the `0x08f4` path.

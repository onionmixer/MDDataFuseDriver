# WS60 mdmgr stride-0x11 Index-Bounds Consolidation

Date: 2026-02-17

## Results
- analyzed lanes: 4
- contains `0x1997` in raw model: 0
- contains `0x1997` in post-init model: 0
- Three stride-`0x11` consumers (`0x07fa`, `0x0879`, `0x08e1`) have explicit `idx<3` guards.
- `0x0916` consumes remapped index via `[0x0d30 + k*0x14]`; init writes force `0xFF` for `k=0..7`, folding to one lane address (`0x0dca`) in that bounded subspace.
- Remaining uncertainty is concentrated on `0x0916` path for `k>=8` (no local bound in this function).

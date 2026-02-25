# WS59 mdmgr 0x0c42 Load-Chain Audit

Date: 2026-02-17

## Key Findings
- `lcall [0x0c42]` consumers: 4 (expected: 4)
- direct `mov` writes to `0x0c42/0x0c44`: 0
- Loader sequence at `0x035f..0x037a` matches DOS open/read/close pattern:
  `AX=0x3d00` (open) -> `int 21h`; `AX=0x4402`, `DX=0x0c42`, `CX=4` (IOCTL read from device) -> `int 21h`; `AH=0x3e` (close) -> `int 21h`.
- Branches between read (`0x0375`) and first consume (`0x0398`): 2; carry/error-like checks: 0.
- Interpretation: in bounded static window, no explicit carry/error branch is observed after the read and before first consume.
- Residual UNKNOWN is therefore dominated by runtime content written into `0x0c42/0x0c44`, not by unresolved static producer multiplicity.

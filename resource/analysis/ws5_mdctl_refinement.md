# WS5 MDCTL/IOCTL Refinement Notes

Date: 2026-02-16

## Why this pass
Prior notes treated some `mdcache.exe` IOCTL observations as direct MDCTL-command evidence.
Deeper x86 disassembly shows a more conservative interpretation is required.

## Key findings

1. `0x3ba2` is `strlen`-style helper (far pointer scan to NUL).
- Evidence: `ES:DI` scan with `repne scasb`, returns length in `AX`.

2. `0x3d29` is DOS write wrapper (`AH=0x40`).
- Signature:
  - `BX=[bp+6]` handle
  - `DS:DX=[bp+8]` buffer
  - `CX=[bp+0xc]` length
  - `int 21h`
- `0x3bc3` is buffered write variant with LF->CRLF expansion before calling `0x3d29`.

3. `0x25b6` remains a generic `AH=0x44` wrapper.
- Surface signature:
  - `AL=[bp+8]`, `BX=[bp+6]`, `DS:DX=[bp+0xa]`, `CX=[bp+0xe]`
  - `int 21h`
- In currently recovered direct callsites, observed `AL` values are `0` and `1`.
  - This is compatible with DOS standard handle-device-info flow (`4400h` / `4401h`).
  - Therefore these local callsites alone do not prove MD-specific private opcode payload.

## Impact on confidence
- Keep: DOS tools use device-handle + `INT 21h` control/open/read/write path.
- Downgrade: direct mapping from observed `AH=44h` snippets to MDCTL private opcode table.
- Still unresolved:
  - complete MDCTL opcode/payload matrix
  - proof-level binding between each observed IOCTL callsite and a specific MDCTL command semantic


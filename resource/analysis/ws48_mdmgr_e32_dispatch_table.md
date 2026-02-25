# WS48 mdmgr 0x0e32 Dispatch Table Semantics

Date: 2026-02-17

## Entry Summary
| entry | low | high | init_low | init_high | writes | reads |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | 0x0e32 | 0x0e34 | 0x2606 | 0x478a | 0 | 8 |
| 1 | 0x0e36 | 0x0e38 | 0xb402 | 0x6b00 | 2 | 0 |
| 2 | 0x0e3a | 0x0e3c | 0x14c0 | 0x2e05 | 0 | 0 |

## Indexed Dispatch Evidence
- `0x1cdd: shl ax, 2` (index stride 4 bytes per entry)
- `0x1ce2: mov ax, word ptr [bx + 0xe32]`
- `0x1ce6: or ax, word ptr [bx + 0xe34]` (null guard)
- `0x1cff: lcall [bx + 0xe32]`

## Dispatch Context Hits
- `0x1ce2:mov ax, word ptr [bx + 0xe32]`
- `0x1ce6:or ax, word ptr [bx + 0xe34]`
- `0x1cff:lcall [bx + 0xe32]`

## Notable Write
- Entry #1 (`0x0e36/0x0e38`) is explicitly initialized in code: `0x19db`/`0x19d5`.
- Entry #0 (`0x0e32/0x0e34`) and entry #2 (`0x0e3a/0x0e3c`) have no literal in-image writes in this pass.

## Conclusion
- `0x0e32` is a base of an 8-entry far-pointer dispatch table (startup-init
  zeroes all 8 entries per `WS54`), not a single callback slot. Only entries
  0..2 have dispatch/write evidence in this bounded static pass.
- Provider confidence improves for entry #1 (code-initialized), while entry #0/#2 still require runtime/relocation-aware closure.

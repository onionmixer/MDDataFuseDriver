# WS18 mdfsck `0x3cca` Parameter Map (Conservative)

Date: 2026-02-17

## Scope
- Binary: `w31/extract/mdfsck.exe`
- Function window: memory `0x3cca..0x3df2`
- Goal: infer argument-to-header-field mapping without over-claiming semantics.

## Observed Writes
- `0x3d2d: mov word ptr es:[bx + 0x10], cx` where `cx <- [bp+0x0c]`
- `0x3d31: mov word ptr es:[bx + 0x12], si` where `si <- [bp+0x0e]`
- `0x3d38: mov word ptr es:[bx + 0x14], cx` where `cx <- [bp+0x10]`
- `0x3cd0..0x3cf7`: `si <- [bp+0x10]; shl si, 0x0b; len <- si + 0x18`
- `0x3d13`: `mov byte ptr es:[bx], 1` (type lane)
- `0x3d17..0x3d23`: mode-dependent subtype byte at `es:[bx+1]` (`0x16/0x18`)

## Wrapper-Injected Mode
- `0x3df2` calls `0x3cca` with pushed mode `0`.
- `0x3e12` calls `0x3cca` with pushed mode `1`.
- In `0x3cca`, `arg@[bp+0x14]` controls payload copy direction around tx/rx.

## Conservative Argument Map
| 0x3cca arg slot | Internal use | Confidence |
| --- | --- | --- |
| `[bp+0x06]` | transport handle passed to tx/rx imports | CONFIRMED |
| `[bp+0x08],[bp+0x0a]` | caller payload pointer used for copy-in/out | CONFIRMED |
| `[bp+0x0c],[bp+0x0e]` | written as 32-bit header field at `+0x10/+0x12` | CONFIRMED |
| `[bp+0x10]` | written at header `+0x14`; also drives transfer length (`<<11`) | CONFIRMED |
| `[bp+0x14]` | direction/mode selector (`0` or `1`) | CONFIRMED |

## Semantics (Inferred, not final)
- Header `+0x10/+0x12` behaves like a 32-bit start/index parameter.
- Header `+0x14` behaves like a count/extent parameter in transfer units of `0x800` bytes.
- Effective payload length follows: `len_bytes ~= ([bp+0x10] << 11) + 0x18`.

## Limits
- Field names (e.g., exact "LBA", "cluster", "record-id") are not proven.
- Runtime reachability of this helper cluster is not confirmed by direct near-call CFG from entry (`WS17`).
- Dynamic trace is required to upgrade inferred names to confirmed protocol semantics.

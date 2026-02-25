# WS38 mdfsck Runtime Vector Slot Trace (Static)

Date: 2026-02-17

| slot | total_refs | writes | indirect_calls/jmps | tests |
| --- | --- | --- | --- | --- |
| 0x14d2 | 1 | 0 | 1 | 0 |
| 0x14d6 | 2 | 0 | 1 | 0 |
| 0x14dc | 2 | 1 | 1 | 0 |
| 0x177a | 2 | 0 | 1 | 0 |
| 0x196c | 3 | 0 | 3 | 0 |

## Per-slot details

### 0x14d2
- 0x422e `lcall [0x14d2]` (indirect)

### 0x14d6
- 0x4259 `mov ax, word ptr [0x14d6]` (read)
- 0x4264 `ljmp [0x14d6]` (indirect)

### 0x14dc
- 0x428c `pop word ptr [0x14dc]` (write)
- 0x4430 `ljmp [0x14dc]` (indirect)

### 0x177a
- 0x5b48 `or cx, word ptr [0x177a]` (read)
- 0x5b51 `lcall [0x177a]` (indirect)

### 0x196c
- 0x40d1 `lcall [0x196c]` (indirect)
- 0x40e4 `lcall [0x196c]` (indirect)
- 0x41f9 `lcall [0x196c]` (indirect)

## Notes
- Slots with only indirect use and no in-image concrete writes are likely runtime-populated vectors.
- This pass is static only; runtime value capture is still needed for final reachability closure.

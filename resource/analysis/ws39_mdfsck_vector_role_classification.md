# WS39 mdfsck Runtime Vector Role Classification

Date: 2026-02-17

## Input Evidence
- `analysis/ws30_mdfsck_indirect_flow.md`
- `analysis/ws38_mdfsck_runtime_vector_slots.md`
- direct disassembly windows around `0x421c..0x4434`, `0x5b40..0x5b63`

## Per-slot Classification (Static)

### 0x196c
- Observed only as `lcall [0x196c]` (`0x40d1`, `0x40e4`, `0x41f9`), no in-image write.
- Nearby context is process/handler setup and vector operations (`int 0x21` setup around same region).
- Classification: runtime-populated service callback vector (`INFERRED`).

### 0x14d2 / 0x14d4
- `0x4227: cmp [0x14d4],0` gate; if nonzero -> `0x422e: lcall [0x14d2]`.
- Classification: optional runtime callback pair (enable flag + far target) (`INFERRED`).

### 0x14d6
- `0x4259: mov ax,[0x14d6]`; sentinel check then `0x4264: ljmp [0x14d6]`.
- Classification: runtime far-jump continuation/error-exit vector (`INFERRED`).

### 0x14dc / 0x14de
- `0x428c/0x4290`: far pointer words popped from stack into slot.
- `0x4430: ljmp [0x14dc]` after argv/env build block.
- Classification: saved return/continuation far pointer slot (`INFERRED`).

### 0x177a / 0x177c
- `0x5b44: mov cx,[0x177c]` + `or cx,[0x177a]`; if nonzero then `lcall [0x177a]`.
- Classification: secondary optional callback + presence check (`INFERRED`).

## Reachability Impact
- Unresolved vectors concentrate around runtime callback/continuation mechanics.
- No static evidence that these vectors are intended to dispatch into `0x3994..0x3f4a` helper cluster.
- Final closure still requires runtime target capture at call sites.

## Confidence Update
- UNKNOWN is narrowed from “unresolved indirect calls” to “runtime callback targets unresolved”.

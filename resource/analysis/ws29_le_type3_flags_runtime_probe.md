# WS29 LE Type-3 Flags Runtime Probe

Date: 2026-02-17
Status: runtime mutation probe plan (prepared)

## Objective
Empirically constrain bit-level semantics of LE type-3 flags byte (currently invariant `0x03`).

## Target Files
- `w95/extract/us/mdmgr.vxd`
- `w95/extract/us/mdhlp.vxd`
- `w95/extract/us/mdfsd.vxd`

## Mutation Set (disposable copies only)
- baseline: `0x03` (control)
- trial A: `0x01`
- trial B: `0x02`
- trial C: `0x00`
- trial D: `0x07`

## Probe Method
1. Make per-trial copied VxD set.
2. Patch ordinal-1 type-3 entry flags byte only.
3. Boot Win95 test VM and load/install stack.
4. Observe:
- loader acceptance/rejection
- module load order and presence
- DDB registration side effects
- filesystem stack behavior (mount/check path)

## Success/Failure Signals
- If only `0x03` loads while others fail: strong evidence flags are strict-required for DDB type-3 entry.
- If multiple values load with identical behavior: flags likely contain non-critical/reserved bits.
- If behavior changes by bit pattern: infer bit-level roles and promote to bounded semantics.

## Logging Format
- `trial,driver,flags_before,flags_after,load_result,error_signature,behavior_notes`

## Safety
- never patch original extracted binaries; keep immutable baseline hashes.
- execute only in disposable VM snapshots.

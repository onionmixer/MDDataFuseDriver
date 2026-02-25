# WS66 mdmgr req[+1] Domain Plausibility (Second Dispatch)

Date: 2026-02-17

Scope: guard-bounded domain `req[+1]=9..13` for `0x0e58 -> cs:[bx+0x07df]`.

## Findings
- plausible jump-entry targets in domain: 1/5
- `0x1047` is the only in-image target with immediate `bp+arg` usage pattern compatible with direct jump from handler frame.
- `0x00b4` is in-image but not an instruction-boundary target (mid-instruction entry), making it non-plausible as direct dispatch destination.
- Off-image targets remain non-plausible without external materialization not evidenced in current static pass.

# WS55 mdmgr 0x0e32 Dispatch State Timeline

Date: 2026-02-17

| phase | entry0 | entry1 | entry2 | evidence |
| --- | --- | --- | --- | --- |
| raw_image | 478a:2606 | 6b00:b402 | 2e05:14c0 | on-disk words |
| startup_zero_loop | 0000:0000 | 0000:0000 | 0000:0000 | 0x2e7f/0x2e85 over i=0..7 |
| startup_set_entry0 | 0073:0601 | 0000:0000 | 0000:0000 | 0x2ed8/0x2ede and 0x2efa/0x2f00 |
| runtime_rebind_entry1_observed | 0073:0601(?) | 011f:095c | 0000:0000(?) | 0x19d5/0x19db writes; ordering vs startup unresolved statically |

## Interpretation
- Runtime baseline immediately after startup init is `entry0=0073:0601`, `entry1=0`, `entry2=0`.
- Entry #1 in-image pointer (`011f:095c`) is observed as explicit write in another code path, but static ordering relative to startup path remains unresolved.
- Entry #2 provider remains unresolved; no direct/non-literal static write found in current bounded passes.

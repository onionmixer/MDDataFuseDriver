# WS15 mdfsck Payload Shape Matrix

Date: 2026-02-17

| func_mem | lengths | type_values | sub_values | tx_calls | rx_calls | nested_calls |
| --- | --- | --- | --- | --- | --- | --- |
| 0x3cca |  | 0x1 | 0x16/0x18 | 1 | 1 |  |
| 0x3e32 |  |  |  | 0 | 0 | 0x3a4c,0x3adc |
| 0x3e72 | 0x11 | 0x2 | 0x8 | 1 | 1 |  |
| 0x3ef0 | 0x17 | 0x1 | 0x24 | 1 | 0 |  |
| 0x3f4a | 0x10 | 0x1 | 0x7 | 1 | 0 |  |

## Notes
- `0x3cca` uses `type=1` and computes subtype-like byte as `0x16/0x18` from mode arg.
- `0x3e32` is an orchestrator that sequences `0x3a4c` then `0x3adc` (both `type=2` frame families).
- `0x3e72` builds `type=2,sub=8,len=0x11` frame pair (tx+rx).
- `0x3ef0` and `0x3f4a` are `type=1` control/info probes with compact frame lengths.
- This matrix is payload-shape evidence only, not final opcode semantics.

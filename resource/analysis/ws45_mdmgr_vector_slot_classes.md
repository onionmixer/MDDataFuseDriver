# WS45 mdmgr Vector Slot Classes

Date: 2026-02-17

Target: `w31/extract/mdmgr.exe`

| slot | class | lcall sites | guard sites (`mov ax,[slot]; or ax,[slot+2]`) |
| --- | --- | --- | --- |
| 0x0c42 | parser_callback | 4 | 0 |
| 0x0cfa | device_vector | 1 | 1 |
| 0x0cfe | device_vector | 1 | 1 |
| 0x0e2a | device_vector | 1 | 1 |
| 0x0e2e | device_vector | 1 | 1 |
| 0x0e32 | device_vector | 5 | 0 |

## Zero-init evidence
- `0x0be5: mov word ptr [0xcfc], 0` (slot `0x0cfc`)
- `0x0beb: mov word ptr [0xcfa], 0` (slot `0x0cfa`)
- `0x0bf1: mov word ptr [0xd00], 0` (slot `0x0d00`)
- `0x0bf7: mov word ptr [0xcfe], 0` (slot `0x0cfe`)
- `0x19bd: mov word ptr [0xe2c], 0` (slot `0x0e2c`)
- `0x19c3: mov word ptr [0xe2a], 0` (slot `0x0e2a`)
- `0x19c9: mov word ptr [0xe30], 0` (slot `0x0e30`)
- `0x19cf: mov word ptr [0xe2e], 0` (slot `0x0e2e`)

## Notes
- `0x0c42` is used as parser-style callback with stack pointer argument blocks in multiple command handlers.
- `0x0cfa/0x0cfe` and `0x0e2a/0x0e2e` show paired low/high-word guard checks before optional `lcall`.
- `0x0e32` is a high-frequency helper vector used by multiple request builders.

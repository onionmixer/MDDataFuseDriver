# WS46 mdmgr Vector Population Provenance

Date: 2026-02-17

| low | high | class | provider | writes | guards | calls | note |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0x0c42 | 0x0c44 | parser_callback | ioctl_read_int21_4402 | 0 | 0 | 4 | buffer=0x0c42, len=4, at 0x0375 |
| 0x0cfa | 0x0cfc | device_hook_a | zero_init_only | 2 | 1 | 1 | low/high words explicitly zeroed, no non-zero in-image writes |
| 0x0cfe | 0x0d00 | device_hook_b | zero_init_only | 2 | 1 | 1 | low/high words explicitly zeroed, no non-zero in-image writes |
| 0x0e2a | 0x0e2c | device_hook_c | zero_init_only | 2 | 1 | 1 | low/high words explicitly zeroed, no non-zero in-image writes |
| 0x0e2e | 0x0e30 | device_hook_d | zero_init_only | 2 | 1 | 1 | low/high words explicitly zeroed, no non-zero in-image writes |
| 0x0e32 | 0x0e34 | dispatch_table_base | unknown_runtime | 0 | 0 | 5 |  |

## IOCTL-read population evidence
- `int 21h` (`AX=0x4402` = IOCTL Read from character device) at `0x0375` with `DX=0x0c42`, `CX=4`

## Conclusion
- `0x0c42` is explicitly populated via DOS IOCTL read (`int 21h/4402`) before callback use.
- Guarded device-hook pairs (`0x0cfa/0x0cfc`, `0x0cfe/0x0d00`, `0x0e2a/0x0e2c`, `0x0e2e/0x0e30`) are zero-initialized in-image and guarded before `lcall`.
- No non-zero in-image writes were found for guarded hook pairs in this pass; non-null values, if any, likely come from runtime/external initialization.

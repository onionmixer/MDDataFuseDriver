# WS44 Cross-binary Callback ABI Parity

Date: 2026-02-17

Scope: compare `mdfsck` slot `0x196c` flow with `mdfsex` slot `0x065c` flow.

| binary | slot | gate_slot | site | prelude | gate_context |
| --- | --- | --- | --- | --- | --- |
| mdfsck | 0x196c | 0x196e | 0x40d1 | 0x40c3:mov si, word ptr es:[0x2c] ; 0x40c8:mov ax, word ptr [0x1970] ; 0x40cb:mov dx, word ptr [0x1972] ; 0x40cf:xor bx, bx | 0x40b8:pop ds || 0x40b9:mov cx, word ptr [0x196e] || 0x40bd:jcxz 0x40e8 || 0x40bf:mov es, word ptr [0x149a] |
| mdfsck | 0x196c | 0x196e | 0x40e4 | 0x40da:mov ax, word ptr [0x1974] ; 0x40dd:mov dx, word ptr [0x1976] ; 0x40e1:mov bx, 3 | 0x40b8:pop ds || 0x40b9:mov cx, word ptr [0x196e] || 0x40bd:jcxz 0x40e8 || 0x40bf:mov es, word ptr [0x149a] |
| mdfsck | 0x196c | 0x196e | 0x41f9 | 0x41f0:mov cx, word ptr [0x196e] ; 0x41f6:mov bx, 2 | 0x41ef:retf  || 0x41f0:mov cx, word ptr [0x196e] || 0x41f4:jcxz 0x41fd || 0x41f6:mov bx, 2 |

- `mdfsck` call sites found: 3

| mdfsex | 0x065c | 0x065e | 0x0146 | 0x0138:mov si, word ptr es:[0x2c] ; 0x013d:mov ax, word ptr [0x660] ; 0x0140:mov dx, word ptr [0x662] ; 0x0144:xor bx, bx | - |
| mdfsex | 0x065c | 0x065e | 0x0159 | 0x014f:mov ax, word ptr [0x664] ; 0x0152:mov dx, word ptr [0x666] ; 0x0156:mov bx, 3 | - |
| mdfsex | 0x065c | 0x065e | 0x0275 | 0x026c:mov cx, word ptr [0x65e] ; 0x0272:mov bx, 2 | 0x026b:ret  || 0x026c:mov cx, word ptr [0x65e] || 0x0270:jcxz 0x279 || 0x0272:mov bx, 2 |

- `mdfsex` call sites found: 3

## Findings
- Both binaries show `mov cx,[gate]` + `jcxz` style gate before `lcall [slot]` paths.
- Both binaries use staged register setup (`AX:DX` payload lanes + `BX` selector) before indirect far calls.
- This supports a shared runtime callback ABI pattern between checker (`mdfsck`) and extractor (`mdfsex`).

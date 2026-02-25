# WS16 mdfsck `0x3cca` Semantics

Date: 2026-02-17

## 1) Wrapper Entry Points
- `0x3df2` pushes literal `0` then forwards args to `0x3cca`.
- `0x3e12` pushes literal `1` then forwards args to `0x3cca`.

### `0x3df2`
```asm
0x3df2: push bp
0x3df3: mov bp, sp
0x3df5: push 0
0x3df7: push word ptr [bp + 0x12]
0x3dfa: push word ptr [bp + 0x10]
0x3dfd: push word ptr [bp + 0xe]
0x3e00: push word ptr [bp + 0xc]
0x3e03: push word ptr [bp + 0xa]
0x3e06: push word ptr [bp + 8]
0x3e09: push word ptr [bp + 6]
0x3e0c: push cs
0x3e0d: call 0x3cca
0x3e10: leave
0x3e11: retf
```

### `0x3e12`
```asm
0x3e12: push bp
0x3e13: mov bp, sp
0x3e15: push 1
0x3e17: push word ptr [bp + 0x12]
0x3e1a: push word ptr [bp + 0x10]
0x3e1d: push word ptr [bp + 0xe]
0x3e20: push word ptr [bp + 0xc]
0x3e23: push word ptr [bp + 0xa]
0x3e26: push word ptr [bp + 8]
0x3e29: push word ptr [bp + 6]
0x3e2c: push cs
0x3e2d: call 0x3cca
0x3e30: leave
0x3e31: retf
```

## 2) Core `0x3cca` Evidence Lines
```asm
0x3cd0: mov si, word ptr [bp + 0x10]
0x3cd3: shl si, 0xb
0x3d13: mov byte ptr es:[bx], 1
0x3d17: cmp word ptr [bp + 0x14], 1
0x3d20: add cl, 0x18
0x3d2d: mov word ptr es:[bx + 0x10], cx
0x3d31: mov word ptr es:[bx + 0x12], si
0x3d38: mov word ptr es:[bx + 0x14], cx
0x3d3c: cmp word ptr [bp + 0x14], ax
0x3d5b: rep movsw word ptr es:[di], word ptr [si]
0x3d6e: lcall 0x3f7, 0x1396
0x3da3: lcall 0x3f7, 0x1298
0x3dca: cmp word ptr [bp + 0x14], 0
0x3de4: rep movsw word ptr es:[di], word ptr [si]
```

## 3) Conservative Parameter Interpretation
- `arg@+14` is a direction flag injected by wrappers (`0` vs `1`).
- Request header starts with `type=1` (`mov byte ptr es:[bx],1`).
- Header subtype-like byte is derived from direction/mode path:
  `cmp mode,1; sbb cl,cl; and cl,0xfe; add cl,0x18` => mode `0 -> 0x16`, mode `1 -> 0x18`.
- `arg@+10` is transformed by `<<11` and used in length math (`len = (arg<<11)+0x18`).
- For `arg@+14 != 0`, payload is copied from caller buffer into tx frame before send.
- Send call: `lcall 0x3f7,0x1396`; receive call: `lcall 0x3f7,0x1298`.
- For `arg@+14 == 0`, payload is copied from rx frame back to caller buffer.

## 4) Limits
- This establishes request/response direction semantics and frame-length behavior.
- It does not yet identify exact field names for header words at `+0x10/+0x12/+0x14`.
- It does not by itself map these fields to on-disk VD member offsets.

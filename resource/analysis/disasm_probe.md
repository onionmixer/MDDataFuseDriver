# Disassembly Probe

Date: 2026-02-16

## w31/extract/mdfsex.exe
- entry_off_guess: 0x0000b850
```asm
0x0000b850: mov bp, ax
0x0000b852: mov ax, es
0x0000b854: add ax, 0x10
0x0000b857: push cs
0x0000b858: pop ds
0x0000b859: mov word ptr [4], ax
0x0000b85c: add ax, word ptr [0xc]
0x0000b860: mov es, ax
0x0000b862: mov cx, word ptr [6]
0x0000b866: mov di, cx
0x0000b868: dec di
0x0000b869: mov si, di
0x0000b86b: std
0x0000b86c: rep movsb byte ptr es:[di], byte ptr [si]
0x0000b86e: push ax
0x0000b86f: mov ax, 0x34
0x0000b872: push ax
0x0000b873: retf
0x0000b874: mov bx, es
0x0000b876: mov ax, ds
0x0000b878: dec ax
0x0000b879: mov ds, ax
0x0000b87b: mov es, ax
0x0000b87d: mov di, 0xf
0x0000b880: mov cx, 0x10
0x0000b883: mov al, 0xff
0x0000b885: repe scasb al, byte ptr es:[di]
0x0000b887: inc di
0x0000b888: mov si, di
0x0000b88a: mov ax, bx
0x0000b88c: dec ax
0x0000b88d: mov es, ax
0x0000b88f: mov di, 0xf
0x0000b892: mov cl, 4
0x0000b894: mov ax, si
0x0000b896: not ax
0x0000b898: shr ax, cl
0x0000b89a: mov dx, ds
0x0000b89c: sub dx, ax
0x0000b89e: jae 0xb8a4
```

## w31/extract/mdfsck.exe
- entry_off_guess: 0x0000478e
```asm
0x0000478e: mov ah, 0x30
0x00004790: int 0x21
0x00004792: cmp al, 2
0x00004794: jae 0x479b
0x00004796: xor ax, ax
0x00004798: push es
0x00004799: push ax
0x0000479a: retf
0x0000479b: mov di, 0xdcd
0x0000479e: mov si, word ptr [2]
0x000047a2: sub si, di
0x000047a4: cmp si, 0x1000
0x000047a8: jb 0x47ad
0x000047aa: mov si, 0x1000
0x000047ad: cli
0x000047ae: mov ss, di
0x000047b0: add sp, 0x667e
0x000047b4: sti
0x000047b5: jae 0x47c9
0x000047b7: push ss
0x000047b8: pop ds
0x000047b9: push cs
0x000047ba: call 0x4a1c
0x000047bd: xor ax, ax
0x000047bf: push ax
0x000047c0: push cs
0x000047c1: call 0x4cff
0x000047c4: mov ax, 0x4cff
0x000047c7: int 0x21
0x000047c9: mov word ptr ss:[0x149e], ax
0x000047cd: xchg al, ah
0x000047cf: mov word ptr ss:[0x149c], ax
0x000047d3: mov ax, si
0x000047d5: mov cl, 4
0x000047d7: shl ax, cl
0x000047d9: dec ax
0x000047da: mov word ptr ss:[0x145c], ax
0x000047de: mov bx, 0x145e
0x000047e1: mov word ptr ss:[bx], ss
0x000047e4: and sp, 0xfffe
```

## w31/extract/mdformat.exe
- entry_off_guess: 0x00001c00
```asm
0x00001c00: mov dx, 0x170d
0x00001c03: mov word ptr cs:[0x26d], dx
0x00001c08: mov ah, 0x30
0x00001c0a: int 0x21
0x00001c0c: mov bp, word ptr [2]
0x00001c10: mov bx, word ptr [0x2c]
0x00001c14: mov ds, dx
0x00001c16: mov word ptr [0x7c], ax
0x00001c19: mov word ptr [0x7a], es
0x00001c1d: mov word ptr [0x76], bx
0x00001c21: mov word ptr [0x8e], bp
0x00001c25: call 0x1d78
0x00001c28: mov ax, word ptr [0x76]
0x00001c2b: mov es, ax
0x00001c2d: xor ax, ax
0x00001c2f: mov bx, ax
0x00001c31: mov di, ax
0x00001c33: mov cx, 0x7fff
0x00001c36: cld
0x00001c37: repne scasb al, byte ptr es:[di]
0x00001c39: jcxz 0x1c7e
0x00001c3b: inc bx
0x00001c3c: cmp byte ptr es:[di], al
0x00001c3f: jne 0x1c37
0x00001c41: or ch, 0x80
0x00001c44: neg cx
0x00001c46: mov word ptr [0x74], cx
0x00001c4a: mov cx, 2
0x00001c4d: shl bx, cl
0x00001c4f: add bx, 0x10
0x00001c52: and bx, 0xfff0
0x00001c55: mov word ptr [0x78], bx
0x00001c59: mov dx, ss
0x00001c5b: sub bp, dx
0x00001c5d: mov di, 0x170d
0x00001c60: mov es, di
0x00001c62: mov di, word ptr es:[0x15d2]
0x00001c67: cmp di, 0x200
0x00001c6b: jae 0x1c75
0x00001c6d: mov di, 0x200
```

## w31/extract/mdcache.exe
- entry_off_guess: 0x00001000
```asm
0x00001000: mov dx, 0xb8a
0x00001003: mov word ptr cs:[0x26d], dx
0x00001008: mov ah, 0x30
0x0000100a: int 0x21
0x0000100c: mov bp, word ptr [2]
0x00001010: mov bx, word ptr [0x2c]
0x00001014: mov ds, dx
0x00001016: mov word ptr [0x7c], ax
0x00001019: mov word ptr [0x7a], es
0x0000101d: mov word ptr [0x76], bx
0x00001021: mov word ptr [0x8e], bp
0x00001025: call 0x1178
0x00001028: mov ax, word ptr [0x76]
0x0000102b: mov es, ax
0x0000102d: xor ax, ax
0x0000102f: mov bx, ax
0x00001031: mov di, ax
0x00001033: mov cx, 0x7fff
0x00001036: cld
0x00001037: repne scasb al, byte ptr es:[di]
0x00001039: jcxz 0x107e
0x0000103b: inc bx
0x0000103c: cmp byte ptr es:[di], al
0x0000103f: jne 0x1037
0x00001041: or ch, 0x80
0x00001044: neg cx
0x00001046: mov word ptr [0x74], cx
0x0000104a: mov cx, 2
0x0000104d: shl bx, cl
0x0000104f: add bx, 0x10
0x00001052: and bx, 0xfff0
0x00001055: mov word ptr [0x78], bx
0x00001059: mov dx, ss
0x0000105b: sub bp, dx
0x0000105d: mov di, 0xb8a
0x00001060: mov es, di
0x00001062: mov di, word ptr es:[0xa54]
0x00001067: cmp di, 0x200
0x0000106b: jae 0x1075
0x0000106d: mov di, 0x200
```

## w31/extract/mdmgr.exe
- entry_off_guess: 0x00000200
```asm
0x00000200: ljmp 0x2dd:0
0x00000205: pop bx
0x00000206: push cs
0x00000207: push bx
0x00000208: cmp cl, 0x10
0x0000020b: jae 0x21d
0x0000020d: mov bx, ax
0x0000020f: shl ax, cl
0x00000211: shl dx, cl
0x00000213: neg cl
0x00000215: add cl, 0x10
0x00000218: shr bx, cl
0x0000021a: or dx, bx
0x0000021c: retf
0x0000021d: sub cl, 0x10
0x00000220: xchg dx, ax
0x00000221: xor ax, ax
0x00000223: shl dx, cl
0x00000225: retf
0x00000226: push bp
0x00000227: mov bp, sp
0x00000229: mov bx, word ptr [bp + 6]
0x0000022c: mov ax, word ptr [0xc38]
0x0000022f: or ax, word ptr [0xc3a]
0x00000233: je 0x249
0x00000235: mov dx, word ptr [0xc3a]
0x00000239: mov ax, word ptr [0xc38]
0x0000023c: mov word ptr [0xc36], dx
0x00000240: mov word ptr [0xc34], ax
0x00000243: mov word ptr [0xc40], bx
0x00000247: jmp 0x25f
0x00000249: mov dx, word ptr [0xc3e]
0x0000024d: mov ax, word ptr [0xc3c]
0x00000250: mov word ptr [0xc36], dx
0x00000254: mov word ptr [0xc34], ax
0x00000257: mov ax, bx
0x00000259: sub ax, 0x10
0x0000025c: mov word ptr [0xc40], ax
0x0000025f: pop bp
0x00000260: retf
```

## w95/extract/us/mdmgr.vxd
- ddb_off_guess: 0x00001320
```asm
0x00001320: add byte ptr [eax], al
0x00001322: add byte ptr [eax], al
0x00001324: add byte ptr [eax + eax], al
0x00001327: add byte ptr [ecx], al
0x00001329: add byte ptr [eax], al
0x0000132b: add byte ptr [ebp + 0x44], cl
0x0000132e: dec ebp
0x0000132f: inc edi
0x00001330: push edx
0x00001331: and byte ptr [eax], ah
0x00001333: and byte ptr [eax], al
0x00001335: add byte ptr [eax], al
0x00001337: add byte ptr [eax], 0
0x0000133a: add byte ptr [eax], al
0x0000133c: add byte ptr [eax], al
0x0000133e: add byte ptr [eax], al
0x00001340: add byte ptr [eax], al
0x00001342: add byte ptr [eax], al
0x00001344: add byte ptr [eax], al
0x00001346: add byte ptr [eax], al
0x00001348: add byte ptr [eax], al
0x0000134a: add byte ptr [eax], al
0x0000134c: add byte ptr [eax], al
0x0000134e: add byte ptr [eax], al
0x00001350: add byte ptr [eax], al
0x00001352: add byte ptr [eax], al
0x00001354: add byte ptr [eax], al
0x00001356: add byte ptr [eax], al
0x00001358: add byte ptr [eax], al
0x0000135a: add byte ptr [eax], al
0x0000135c: jbe 0x13c3
0x0000135e: jb 0x13b0
0x00001360: add byte ptr [eax], al
0x00001362: add byte ptr [eax], al
0x00001364: add byte ptr [eax], al
0x00001366: add byte ptr [eax], al
0x00001368: add byte ptr [eax], al
0x0000136a: add byte ptr [eax], al
0x0000136c: add byte ptr [eax], al
0x0000136e: add byte ptr [eax], al
```

## w95/extract/us/mdhlp.vxd
- ddb_off_guess: 0x000012bc
```asm
0x000012bc: add byte ptr [eax], al
0x000012be: add byte ptr [eax], al
0x000012c0: add byte ptr [eax + eax], al
0x000012c3: add byte ptr [eax + eax], al
0x000012c6: add byte ptr [eax], al
0x000012c8: dec ebp
0x000012c9: inc esp
0x000012ca: dec eax
0x000012cb: insb byte ptr es:[edi], dx
0x000012cc: jo 0x12ee
0x000012ce: and byte ptr [eax], ah
0x000012d0: add byte ptr [eax], al
0x000012d2: add byte ptr [eax], al
0x000012d8: add byte ptr [eax], al
0x000012da: add byte ptr [eax], al
0x000012dc: add byte ptr [eax], al
0x000012de: add byte ptr [eax], al
0x000012e0: add byte ptr [eax], al
0x000012e2: add byte ptr [eax], al
0x000012e4: add byte ptr [eax], al
0x000012e6: add byte ptr [eax], al
0x000012e8: add byte ptr [eax], al
0x000012ea: add byte ptr [eax], al
0x000012ec: add byte ptr [eax], al
0x000012ee: add byte ptr [eax], al
0x000012f0: add byte ptr [eax], al
0x000012f2: add byte ptr [eax], al
0x000012f4: add byte ptr [eax], al
0x000012f6: add byte ptr [eax], al
0x000012f8: jbe 0x135f
0x000012fa: jb 0x134c
0x000012fc: push eax
0x000012fd: add byte ptr [eax], al
0x000012ff: add byte ptr [ecx], dh
0x00001301: jbe 0x1376
0x00001303: push edx
0x00001304: xor dh, byte ptr [esi + 0x73]
0x00001307: push edx
0x00001308: xor esi, dword ptr [esi + 0x73]
0x0000130b: push edx
```

## w95/extract/us/mdfsd.vxd
- ddb_off_guess: 0x00006200
```asm
0x00006200: add byte ptr [eax], al
0x00006202: add byte ptr [eax], al
0x00006204: add byte ptr [eax + eax], al
0x00006207: add byte ptr [ecx], al
0x00006209: add byte ptr [eax], al
0x0000620b: add byte ptr [ebp + 0x44], cl
0x0000620e: inc esi
0x0000620f: push ebx
0x00006210: inc esp
0x00006211: and byte ptr [eax], ah
0x00006213: and byte ptr [eax], al
0x00006215: add dword ptr [ecx], eax
0x00006217: mov al, byte ptr [0]
0x0000621c: add byte ptr [eax], al
0x0000621e: add byte ptr [eax], al
0x00006220: add byte ptr [eax], al
0x00006222: add byte ptr [eax], al
0x00006224: add byte ptr [eax], al
0x00006226: add byte ptr [eax], al
0x00006228: add byte ptr [eax], al
0x0000622a: add byte ptr [eax], al
0x0000622c: add byte ptr [eax], al
0x0000622e: add byte ptr [eax], al
0x00006230: add byte ptr [eax], al
0x00006232: add byte ptr [eax], al
0x00006234: add byte ptr [eax], al
0x00006236: add byte ptr [eax], al
0x00006238: add byte ptr [eax], al
0x0000623a: add byte ptr [eax], al
0x0000623c: jbe 0x62a3
0x0000623e: jb 0x6290
0x00006240: add byte ptr [eax], al
0x00006242: add byte ptr [eax], al
0x00006244: add byte ptr [eax], al
0x00006246: add byte ptr [eax], al
0x00006248: add byte ptr [eax], al
0x0000624a: add byte ptr [eax], al
0x0000624c: add byte ptr [eax], al
0x0000624e: add byte ptr [eax], al
0x00006250: or al, byte ptr [ebx]
```


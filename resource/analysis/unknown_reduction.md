# Unknown Reduction Notes

Date: 2026-02-16

## w31/extract/mdcache.exe ioctl/al trace
- hits: 3
### int21@0x01607 al_source=mov ax, 0x4400
```asm
pop bp
ret 2
push bp
mov bp, sp
push si
push di
mov ax, 0x4400
mov bx, word ptr [bp + 6]
int 0x21
```
### int21@0x025ca al_source=mov al, byte ptr [bp + 8]
```asm
push si
push di
push ds
lds dx, ptr [bp + 0xa]
mov ah, 0x44
mov al, byte ptr [bp + 8]
mov bx, word ptr [bp + 6]
mov cx, word ptr [bp + 0xe]
int 0x21
```
### int21@0x02acd al_source=mov ax, 0x4400
```asm
mov bx, word ptr [bp + 6]
add bx, bx
test byte ptr [bx + 0x9ab], 2
je 0x2ac7
mov ax, 1
jmp 0x2b16
mov ax, 0x4400
mov bx, word ptr [bp + 6]
int 0x21
```

## w31/extract/mdfsck.exe ioctl/al trace
- hits: 3
### int21@0x0493c al_source=mov ax, 0x4400
```asm
or al, dl
stosb byte ptr es:[di], al
jmp 0x491d
push ss
pop ds
mov bx, 4
and byte ptr [bx + 0x14a6], 0xbf
mov ax, 0x4400
int 0x21
```
### int21@0x058bb al_source=mov ax, 0x4400
```asm
cmp ax, 0x500
jne 0x58b4
mov ah, 0x3e
int 0x21
mov ax, 0x1100
jmp 0x589c
mov byte ptr [bp - 3], 1
mov ax, 0x4400
int 0x21
```
### int21@0x05aab al_source=mov ax, 0x4400
```asm
cmp byte ptr [si], 0xa
je 0x5a86
jmp 0x5a83
push es
pop ds
test byte ptr [bx + 0x14a6], 0x40
je 0x5ac4
mov ax, 0x4400
int 0x21
```

## mdfsck VD string-offset table search
- pattern_found_at: not_found

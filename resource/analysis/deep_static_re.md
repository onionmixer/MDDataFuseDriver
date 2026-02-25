# Deep Static RE Notes

Date: 2026-02-16

## w31/extract/mdfsex.exe
- decoded_insn_count: 160
- ioctl_pattern_hits: 0
- open_device_pattern_hits: 0

## w31/extract/mdcache.exe
- decoded_insn_count: 7824
- ioctl_pattern_hits: 3
```asm
0x015fc: push bp
0x015fd: mov bp, sp
0x015ff: push si
0x01600: push di
0x01601: mov ax, 0x4400
0x01604: mov bx, word ptr [bp + 6]
0x01607: int 0x21
```
```asm
0x025bb: push ds
0x025bc: lds dx, ptr [bp + 0xa]
0x025bf: mov ah, 0x44
0x025c1: mov al, byte ptr [bp + 8]
0x025c4: mov bx, word ptr [bp + 6]
0x025c7: mov cx, word ptr [bp + 0xe]
0x025ca: int 0x21
```
```asm
0x02abb: test byte ptr [bx + 0x9ab], 2
0x02ac0: je 0x2ac7
0x02ac2: mov ax, 1
0x02ac5: jmp 0x2b16
0x02ac7: mov ax, 0x4400
0x02aca: mov bx, word ptr [bp + 6]
0x02acd: int 0x21
```
- open_device_pattern_hits: 1
```asm
0x03413: lds dx, ptr [bp + 6]
0x03416: mov cl, 0xf0
0x03418: and cl, byte ptr [bp + 0xa]
0x0341b: or al, cl
0x0341d: mov ah, 0x3d
0x0341f: int 0x21
```

## w31/extract/mdfsck.exe
- decoded_insn_count: 22364
- ioctl_pattern_hits: 3
```asm
0x0492d: jmp 0x491d
0x0492f: push ss
0x04930: pop ds
0x04931: mov bx, 4
0x04934: and byte ptr [bx + 0x14a6], 0xbf
0x04939: mov ax, 0x4400
0x0493c: int 0x21
```
```asm
0x058ab: mov ah, 0x3e
0x058ad: int 0x21
0x058af: mov ax, 0x1100
0x058b2: jmp 0x589c
0x058b4: mov byte ptr [bp - 3], 1
0x058b8: mov ax, 0x4400
0x058bb: int 0x21
```
```asm
0x05a9d: jmp 0x5a83
0x05a9f: push es
0x05aa0: pop ds
0x05aa1: test byte ptr [bx + 0x14a6], 0x40
0x05aa6: je 0x5ac4
0x05aa8: mov ax, 0x4400
0x05aab: int 0x21
```
- open_device_pattern_hits: 2
```asm
0x0587f: push ds
0x05880: lds dx, ptr [bp + 6]
0x05883: and al, 3
0x05885: or al, bh
0x05887: mov ah, 0x3d
0x05889: int 0x21
```
```asm
0x05981: and al, 3
0x05983: or al, byte ptr [bp - 2]
0x05986: push ds
0x05987: lds dx, ptr [bp + 6]
0x0598a: mov ah, 0x3d
0x0598c: int 0x21
```
- field_offset_candidates_top:
  - disp=0x00 count=17385
  - disp=0x06 count=83
  - disp=0x0a count=70
  - disp=0x08 count=50
  - disp=0x65 count=49
  - disp=0x6e count=40
  - disp=0x6f count=38
  - disp=0x02 count=30
  - disp=0x52 count=29
  - disp=0x0c count=28
  - disp=0x61 count=26
  - disp=0x04 count=24
  - disp=0x69 count=24
  - disp=0x72 count=24
  - disp=0x6c count=23
  - disp=0x74 count=22
  - disp=0x73 count=21
  - disp=0x54 count=17
  - disp=0x0e count=14
  - disp=0x75 count=13
  - disp=0x20 count=12
  - disp=0x44 count=11
  - disp=0x64 count=11
  - disp=0x66 count=11
  - disp=0x49 count=10
  - disp=0x68 count=9
  - disp=0x4c count=8
  - disp=0x78 count=7
  - disp=0x0b count=5
  - disp=0x41 count=5
  - disp=0x53 count=5
  - disp=0x2c count=4
  - disp=0x4d count=4
  - disp=0x2e count=3
  - disp=0x3a count=3
  - disp=0x42 count=3
  - disp=0x45 count=3
  - disp=0x4e count=3
  - disp=0x50 count=3
  - disp=0x70 count=3


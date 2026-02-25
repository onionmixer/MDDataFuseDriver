#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_16


def mz_entry(path: Path):
    b=path.read_bytes()
    return struct.unpack_from('<H',b,0x08)[0]*16 + struct.unpack_from('<H',b,0x16)[0]*16 + struct.unpack_from('<H',b,0x14)[0]


def disasm(path: Path):
    b=path.read_bytes(); base=mz_entry(path)
    md=Cs(CS_ARCH_X86,CS_MODE_16); md.detail=True
    return list(md.disasm(b[base:],base))


def analyze_ioctl_al(ins):
    rows=[]
    for i,x in enumerate(ins):
        if x.mnemonic=='int' and x.op_str=='0x21':
            ctx=ins[max(0,i-8):i+1]
            txt='\n'.join(f"{c.mnemonic} {c.op_str}" for c in ctx)
            if 'ah, 0x44' in txt or 'ax, 0x4400' in txt:
                al_src='unknown'
                for c in reversed(ctx):
                    s=f"{c.mnemonic} {c.op_str}"
                    if 'mov al, ' in s:
                        al_src=s
                        break
                    if 'mov ax, 0x44' in s:
                        al_src=s
                        break
                rows.append((x.address,al_src,txt))
    return rows


def find_string_table(data: bytes, offsets):
    # Search for contiguous little-endian offsets sequence
    pat=b''.join(int(o).to_bytes(2,'little') for o in offsets)
    pos=data.find(pat)
    return pos


def main():
    report=['# Unknown Reduction Notes','', 'Date: 2026-02-16','']

    for f in ['w31/extract/mdcache.exe','w31/extract/mdfsck.exe']:
        ins=disasm(Path(f))
        rows=analyze_ioctl_al(ins)
        report.append(f'## {f} ioctl/al trace')
        report.append(f'- hits: {len(rows)}')
        for addr,al,txt in rows[:20]:
            report.append(f'### int21@0x{addr:05x} al_source={al}')
            report.append('```asm')
            report.append(txt)
            report.append('```')
        report.append('')

    # mdfsck VD string table search
    data=Path('w31/extract/mdfsck.exe').read_bytes()
    vd_offs=[0xe781,0xe793,0xe7a2,0xe7b9,0xe7d4,0xe7ed,0xe80f,0xe836,0xe85b,0xe87c]
    pos=find_string_table(data,vd_offs)
    report.append('## mdfsck VD string-offset table search')
    report.append(f'- pattern_found_at: {pos if pos!=-1 else "not_found"}')
    if pos!=-1:
        lo=max(0,pos-64); hi=min(len(data),pos+128)
        chunk=data[lo:hi]
        report.append('```hex')
        # compact hex dump
        for i in range(0,len(chunk),16):
            part=chunk[i:i+16]
            report.append(f"{lo+i:08x}: {part.hex()}")
        report.append('```')

    Path('analysis/unknown_reduction.md').write_text('\n'.join(report)+'\n',encoding='utf-8')
    print('wrote analysis/unknown_reduction.md')

if __name__=='__main__':
    main()

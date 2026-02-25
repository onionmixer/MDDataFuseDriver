#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_16


def mz_entry(path: Path):
    b=path.read_bytes()
    e_cparhdr=struct.unpack_from('<H',b,0x08)[0]
    ip=struct.unpack_from('<H',b,0x14)[0]
    cs=struct.unpack_from('<H',b,0x16)[0]
    return e_cparhdr*16+cs*16+ip


def disasm(path: Path):
    b=path.read_bytes(); base=mz_entry(path)
    md=Cs(CS_ARCH_X86,CS_MODE_16); md.detail=True
    return list(md.disasm(b[base:],base))


def dump(ins):
    return '\n'.join(f"0x{x.address:05x}: {x.mnemonic} {x.op_str}".rstrip() for x in ins)


def collect_ioctl_contexts(ins):
    hits=[]
    for i,x in enumerate(ins):
        s=f"{x.mnemonic} {x.op_str}"
        if ('ah, 0x44' in s) or ('ax, 0x44' in s):
            ctx=ins[max(0,i-10):min(len(ins),i+10)]
            hits.append(ctx)
    return hits


def collect_int21_contexts(ins):
    hits=[]
    for i,x in enumerate(ins):
        if x.mnemonic=='int' and x.op_str=='0x21':
            ctx=ins[max(0,i-8):min(len(ins),i+4)]
            txt='\n'.join(f"{c.mnemonic} {c.op_str}" for c in ctx)
            if '0x44' in txt or 'ah, 0x3d' in txt or 'ax, 0x3d' in txt:
                hits.append(ctx)
    return hits


def collect_vd_string_refs(ins):
    # wide net: search push/mov immediates in 0xE700~0xEA40 region
    hits=[]
    for i,x in enumerate(ins):
        s=f"{x.mnemonic} {x.op_str}"
        for h in ['0xe7','0xe8','0xe9','0xea']:
            if h in s and any(k in s for k in ['mov dx,','push ','mov ax,']):
                ctx=ins[max(0,i-8):min(len(ins),i+10)]
                hits.append(ctx)
                break
    return hits


def write_section(report,title,hits,limit=20):
    report.append(f'## {title}')
    report.append(f'- hits: {len(hits)}')
    for i,ctx in enumerate(hits[:limit],1):
        report.append(f'### hit_{i}')
        report.append('```asm')
        report.append(dump(ctx))
        report.append('```')
    report.append('')


def main():
    report=['# IOCTL/VD Pattern Trace v2','', 'Date: 2026-02-16','']
    for f in ['w31/extract/mdcache.exe','w31/extract/mdfsck.exe','w31/extract/mdfsex.exe']:
        ins=disasm(Path(f))
        report.append(f'# File: {f}')
        report.append(f'- decoded_insn_count: {len(ins)}')
        write_section(report,'ioctl_setup_hits',collect_ioctl_contexts(ins),limit=30)
        write_section(report,'int21_ioctl_open_hits',collect_int21_contexts(ins),limit=30)
        if f.endswith('mdfsck.exe'):
            write_section(report,'vd_string_ref_candidate_hits',collect_vd_string_refs(ins),limit=30)

    Path('analysis/ioctl_trace2.md').write_text('\n'.join(report)+'\n',encoding='utf-8')
    print('wrote analysis/ioctl_trace2.md')

if __name__=='__main__':
    main()

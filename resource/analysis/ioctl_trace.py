#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct,re
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


def parse_target(op):
    m=re.match(r'0x([0-9a-fA-F]+)$',op.strip())
    return int(m.group(1),16) if m else None


def collect_calls(ins, target):
    out=[]
    for i,x in enumerate(ins):
        if x.mnemonic=='call':
            t=parse_target(x.op_str)
            if t==target:
                ctx=ins[max(0,i-12):min(len(ins),i+4)]
                out.append(ctx)
    return out


def dump_ctx(ctx):
    return '\n'.join(f"0x{c.address:05x}: {c.mnemonic} {c.op_str}".rstrip() for c in ctx)


def find_mov_dx_strings(ins, lo, hi):
    hits=[]
    for i,x in enumerate(ins):
        if x.mnemonic=='mov' and x.op_str.startswith('dx, '):
            t=parse_target(x.op_str.split(',')[1].strip())
            if t is not None and lo<=t<=hi:
                hits.append((i,x.address,t))
    return hits


def main():
    report=['# IOCTL and VD Trace','', 'Date: 2026-02-16','']

    # mdcache ioctl wrapper target from prior observation
    p=Path('w31/extract/mdcache.exe')
    ins=disasm(p)
    target=0x25bb
    c=collect_calls(ins,target)
    report.append('## mdcache.exe ioctl wrapper calls')
    report.append(f'- wrapper_addr: 0x{target:05x}')
    report.append(f'- call_sites: {len(c)}')
    for idx,ctx in enumerate(c[:12],1):
        report.append(f'### call_site_{idx}')
        report.append('```asm')
        report.append(dump_ctx(ctx))
        report.append('```')

    # mdfsck volume descriptor print string range around 0xe76d..0xea20
    p2=Path('w31/extract/mdfsck.exe')
    ins2=disasm(p2)
    hits=find_mov_dx_strings(ins2,0xe760,0xea30)
    report.append('')
    report.append('## mdfsck.exe VD print-region mov dx,imm hits')
    report.append(f'- hits: {len(hits)}')
    for n,(i,addr,imm) in enumerate(hits[:40],1):
        report.append(f'### vd_hit_{n} addr=0x{addr:05x} str_off=0x{imm:04x}')
        ctx=ins2[max(0,i-10):min(len(ins2),i+12)]
        report.append('```asm')
        report.append(dump_ctx(ctx))
        report.append('```')

    Path('analysis/ioctl_trace.md').write_text('\n'.join(report)+'\n',encoding='utf-8')
    print('wrote analysis/ioctl_trace.md')

if __name__=='__main__':
    main()

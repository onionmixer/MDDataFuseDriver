#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
import struct,re
from capstone import Cs, CS_ARCH_X86, CS_MODE_16

p=Path('w31/extract/mdfsck.exe')
b=p.read_bytes()
# from strings evidence: first runtime/library string around 0xE4D8
code_end=0xE4D8

# MZ entry base
base=struct.unpack_from('<H',b,0x08)[0]*16 + struct.unpack_from('<H',b,0x16)[0]*16 + struct.unpack_from('<H',b,0x14)[0]
code=b[base:code_end]
md=Cs(CS_ARCH_X86,CS_MODE_16)
ins=list(md.disasm(code,base))

hits=[]
for i,x in enumerate(ins):
    s=f"{x.mnemonic} {x.op_str}".lower()
    # only immediates in VD string area
    for tok in s.replace(',',' ').split():
        if tok.startswith('0x'):
            try: v=int(tok,16)
            except: continue
            if 0xE760 <= v <= 0xEA40:
                hits.append((i,x.address,s,v)); break

print('entry_base',hex(base),'code_end',hex(code_end),'insn',len(ins),'hits',len(hits))
for i,addr,s,v in hits[:40]:
    print('---',hex(addr),hex(v),s)
    for c in ins[max(0,i-8):min(len(ins),i+12)]:
        print(f"0x{c.address:05x}: {c.mnemonic} {c.op_str}".rstrip())

# collect int21 with 44xx only in code section
print('\nIOCTL-like int21 in code section:')
for i,x in enumerate(ins):
    if x.mnemonic=='int' and x.op_str=='0x21':
        ctx='\n'.join(f"{c.mnemonic} {c.op_str}" for c in ins[max(0,i-6):i+1])
        if '0x44' in ctx:
            print('int21@',hex(x.address))
            for c in ins[max(0,i-10):min(len(ins),i+6)]:
                print(f"0x{c.address:05x}: {c.mnemonic} {c.op_str}".rstrip())

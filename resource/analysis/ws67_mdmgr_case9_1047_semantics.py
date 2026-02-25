#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

TARGET = Path('w31/extract/mdmgr.exe')
FUNC = (0x1044, 0x10D3)


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def main() -> None:
    raw = TARGET.read_bytes()
    hdr = u16(raw, 0x08) * 16
    img = raw[hdr:]

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(img[FUNC[0]:FUNC[1]], FUNC[0]))

    rows = []
    for x in ins:
        t = x.op_str.lower().replace(' ', '')
        if x.mnemonic == 'mov' and t.startswith('byteptres:[bx],0x45'):
            rows.append({'field': 'out[0]', 'addr': f'0x{x.address:04x}', 'expr': '0x45', 'branch': 'req[0x17]==0'})
        elif x.mnemonic == 'mov' and t.startswith('byteptres:[bx],0x48'):
            rows.append({'field': 'out[0]', 'addr': f'0x{x.address:04x}', 'expr': '0x48', 'branch': 'req[0x17]!=0'})
        elif x.address == 0x1062:
            rows.append({'field': 'out[5]', 'addr': f'0x{x.address:04x}', 'expr': 'req[0x10]', 'branch': 'req[0x17]==0'})
        elif x.address == 0x1070:
            rows.append({'field': 'out[4]', 'addr': f'0x{x.address:04x}', 'expr': 'req[0x11]', 'branch': 'req[0x17]==0'})
        elif x.address == 0x107e:
            rows.append({'field': 'out[3]', 'addr': f'0x{x.address:04x}', 'expr': 'req[0x12]', 'branch': 'req[0x17]==0'})
        elif x.address == 0x108c:
            rows.append({'field': 'out[2]', 'addr': f'0x{x.address:04x}', 'expr': 'req[0x13]', 'branch': 'req[0x17]==0'})
        elif x.address == 0x109a:
            rows.append({'field': 'out[8]', 'addr': f'0x{x.address:04x}', 'expr': 'req[0x14]', 'branch': 'req[0x17]==0'})
        elif x.address == 0x10b8:
            rows.append({'field': 'out[4]', 'addr': f'0x{x.address:04x}', 'expr': 'req[0x10]', 'branch': 'req[0x17]!=0'})
        elif x.address == 0x10cd:
            rows.append({'field': 'out[7]', 'addr': f'0x{x.address:04x}', 'expr': 'sel', 'branch': 'both'})

    md_lines = [
        '# WS67 mdmgr req[+1]=9 Path (`0x1047`) Semantics',
        '',
        'Date: 2026-02-17',
        '',
        'Scope: second-dispatch plausible target `0x1047` from `req[+1]=9` (`0x0e58` table).',
        '',
        '## Structural Behavior',
        '- Branch key: `req[0x17]` (`cmp byte ptr es:[bx+0x17],0`).',
        '- If zero branch (`0x104f` fallthrough): output tag `out[0]=0x45` and scatter copy from `req[0x10..0x14]` into `out[5],out[4],out[3],out[2],out[8]`; `out[7]=req[0x15]`.',
        '- If non-zero branch (`0x10a7`): output tag `out[0]=0x48`; `out[4]=req[0x10]`; `out[7]=req[0x10]+req[0x14]`.',
        '- No status-byte write (`req+3`) occurs inside `0x1047`; status handling remains in outer caller path.',
        '',
        '## Inference',
        '- `req[+1]=9` likely selects a formatter-like subcommand with two record layouts (`0x45` vs `0x48`) keyed by `req[0x17]`.',
        '- This strengthens practical-subset interpretation from WS66: case `9` is not only jump-plausible but semantically coherent as a structured output builder.',
    ]

    Path('analysis/ws67_mdmgr_case9_1047_semantics.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws67_mdmgr_case9_1047_semantics.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['field', 'addr', 'expr', 'branch'])
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws67_mdmgr_case9_1047_semantics.md and .csv')


if __name__ == '__main__':
    main()

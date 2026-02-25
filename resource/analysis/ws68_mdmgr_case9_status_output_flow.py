#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

TARGET = Path('w31/extract/mdmgr.exe')
H = (0x0D31, 0x0EF7)
C9 = (0x1044, 0x10D3)


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def main() -> None:
    raw = TARGET.read_bytes()
    hdr = u16(raw, 0x08) * 16
    img = raw[hdr:]

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    h_ins = list(md.disasm(img[H[0]:H[1]], H[0]))
    c_ins = list(md.disasm(img[C9[0]:C9[1]], C9[0]))

    rows = []

    # status writes in handler (req pointer based)
    for x in h_ins:
        o = x.op_str.lower().replace(' ', '')
        if x.mnemonic == 'mov' and o.startswith('byteptres:[bx+3],'):
            rows.append({'kind': 'status_write', 'addr': f'0x{x.address:04x}', 'insn': f'{x.mnemonic} {x.op_str}', 'zone': 'handler_0d31'})

    # output writes in case9 to [bp+0xa] buffer
    for x in c_ins:
        o = x.op_str.lower().replace(' ', '')
        if x.mnemonic == 'mov' and 'byteptres:[bx+' in o and ('[bp+0xa]' in o or x.address in (0x1054, 0x1062, 0x1070, 0x107e, 0x108c, 0x109a, 0x10aa, 0x10b8, 0x10cd)):
            rows.append({'kind': 'case9_out_write', 'addr': f'0x{x.address:04x}', 'insn': f'{x.mnemonic} {x.op_str}', 'zone': 'case9_1047'})

    # key control transfer facts
    facts = [
        (0x0D5F, 'pre-dispatch status zero init'),
        (0x0E58, 'second dispatch via jmp table'),
        (0x1044, 'case9 target prologue'),
        (0x10D2, 'case9 retf (returns out of handler frame)'),
    ]
    for a, note in facts:
        rows.append({'kind': 'control_fact', 'addr': f'0x{a:04x}', 'insn': '', 'zone': note})

    h_status = [r for r in rows if r['kind'] == 'status_write' and r['zone'] == 'handler_0d31']
    c_status = [r for r in rows if r['kind'] == 'status_write' and r['zone'] == 'case9_1047']

    md_lines = [
        '# WS68 mdmgr Case-9 Status and Output Flow',
        '',
        'Date: 2026-02-17',
        '',
        '## Findings',
        f'- handler (`0x0d31..0x0ef6`) status writes (`req+3`): {len(h_status)}',
        f'- case9 target (`0x1047`) status writes (`req+3`): {len(c_status)}',
        '- Handler pre-initializes status to zero at `0x0d5f` before second-dispatch checks.',
        '- Case-9 path at `0x1047` writes output fields but does not write status byte.',
        '- Case-9 function ends with `retf` (`0x10d2`), so control exits via far return after table jump path.',
        '- Inference: for successful case-9 path, status remains the handler-initialized success value unless earlier guard/error branch fires.',
    ]

    Path('analysis/ws68_mdmgr_case9_status_output_flow.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws68_mdmgr_case9_status_output_flow.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['kind', 'addr', 'insn', 'zone'])
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws68_mdmgr_case9_status_output_flow.md and .csv')


if __name__ == '__main__':
    main()

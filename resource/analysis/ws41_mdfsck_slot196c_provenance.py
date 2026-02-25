#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

SLOT = 0x196C


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def main() -> None:
    p = Path('w31/extract/mdfsck.exe')
    b = p.read_bytes()
    hdr = u16(b, 0x08) * 16
    img = b[hdr:]

    cs = u16(b, 0x16)
    cs_base = cs << 4
    ds_seg = u16(img, cs_base + 0x12E)
    ds_base = ds_seg << 4

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(img, 0))

    rows = []
    for i, x in enumerate(ins):
        text = f"{x.mnemonic} {x.op_str}".lower()
        hit = False
        via = ''

        if f'[0x{SLOT:04x}]' in text.replace(' ', ''):
            hit = True
            via = 'abs_mem'
        elif re.search(rf'\b0x{SLOT:04x}\b', text):
            hit = True
            via = 'imm'

        if not hit:
            continue

        access = 'ref'
        if x.mnemonic in ('call', 'lcall', 'jmp', 'ljmp') and f'[0x{SLOT:04x}]' in text.replace(' ', ''):
            access = 'indirect_call'
        elif x.mnemonic.startswith('mov') and x.op_str.strip().lower().startswith('word ptr [0x'):
            access = 'write'
        elif x.mnemonic in ('pop',) and f'[0x{SLOT:04x}]' in text.replace(' ', ''):
            access = 'write'

        ctx = ins[max(0, i - 4): min(len(ins), i + 5)]
        rows.append(
            {
                'addr': f'0x{x.address:04x}',
                'mnemonic': x.mnemonic,
                'op_str': x.op_str,
                'via': via,
                'access': access,
                'context': ' || '.join(f"0x{q.address:04x}:{q.mnemonic} {q.op_str}" for q in ctx),
            }
        )

    slot_lin = ds_base + SLOT
    init_off = u16(img, slot_lin)
    init_seg = u16(img, slot_lin + 2)

    md_lines = [
        '# WS41 mdfsck Slot 0x196c Provenance',
        '',
        'Date: 2026-02-17',
        '',
        '## Setup',
        f'- `CS=0x{cs:04x}` (`CS_base=0x{cs_base:04x}`)',
        f'- `DS=0x{ds_seg:04x}` (`DS_base=0x{ds_base:04x}`)',
        f'- slot linear: `DS_base + 0x{SLOT:04x} = 0x{slot_lin:04x}`',
        f'- image-init far value at slot: `{init_seg:04x}:{init_off:04x}`',
        '',
        '## References to slot/immediate 0x196c',
        '| addr | insn | via | access |',
        '| --- | --- | --- | --- |',
    ]

    for r in sorted(rows, key=lambda x: int(x['addr'], 16)):
        md_lines.append(f"| {r['addr']} | {r['mnemonic']} {r['op_str']} | {r['via']} | {r['access']} |")

    writes = [r for r in rows if r['access'] == 'write']
    ind = [r for r in rows if r['access'] == 'indirect_call']

    md_lines.extend([
        '',
        '## Conclusion',
        f'- indirect call sites using `[0x{SLOT:04x}]`: {len(ind)}',
        f'- static in-image direct writes to `[0x{SLOT:04x}]`: {len(writes)}',
        '- In this static pass, slot `0x196c` behaves as runtime-populated callback/continuation vector.',
    ])

    Path('analysis/ws41_mdfsck_slot196c_provenance.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws41_mdfsck_slot196c_provenance.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['addr', 'mnemonic', 'op_str', 'via', 'access', 'context'])
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws41_mdfsck_slot196c_provenance.md and .csv')


if __name__ == '__main__':
    main()

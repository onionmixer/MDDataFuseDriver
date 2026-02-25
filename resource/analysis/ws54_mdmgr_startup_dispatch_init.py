#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

TARGET = Path('w31/extract/mdmgr.exe')
FUNC = (0x2E58, 0x312E)


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
        m = x.mnemonic.lower()
        o = x.op_str.lower().replace(' ', '')
        hit = False
        kind = ''
        if m == 'mov' and ('+0xe32' in o or '+0xe34' in o or '[0xe32]' in o or '[0xe34]' in o):
            hit = True
            kind = 'e32_table_write'
        if m == 'mov' and ('+0xd02' in o or '+0xd04' in o or '[0xd06]' in o or '[0xd08]' in o):
            hit = True
            kind = 'd02_table_write' if not kind else kind + '+d02'
        if hit:
            rows.append({'addr': f'0x{x.address:04x}', 'insn': f'{x.mnemonic} {x.op_str}', 'kind': kind})

    # operational interpretation from explicit writes
    summary = [
        ('loop_zero_e32', 'for i=0..7: [0xe32+4*i]=0, [0xe34+4*i]=0'),
        ('loop_zero_d02', 'for i=0..7: [0xd02+4*i]=0, [0xd04+4*i]=0'),
        ('set_entry0_e32', '[0xe32]=0x0601, [0xe34]=0x0073 (written twice)'),
        ('set_entry1_d02', '[0xd06]=0x095c, [0xd08]=0x011f'),
    ]

    md_lines = [
        '# WS54 mdmgr Startup Dispatch-table Initialization',
        '',
        'Date: 2026-02-17',
        '',
        'Scope: startup init routine `0x2e58..0x312e`',
        '',
        '## Key writes detected',
    ]
    for r in rows:
        md_lines.append(f"- {r['addr']} `{r['insn']}` ({r['kind']})")

    md_lines.extend([
        '',
        '## Derived runtime state model (post-init)',
    ])
    for k, v in summary:
        md_lines.append(f'- `{k}`: {v}')

    md_lines.extend([
        '',
        '## Correction Note',
        '- On-disk initial words at `0x0e32..0x0e3c` are overwritten by startup init before normal operation.',
        '- Therefore runtime interpretation should prioritize startup-written values over raw image defaults.',
    ])

    Path('analysis/ws54_mdmgr_startup_dispatch_init.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws54_mdmgr_startup_dispatch_init.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['addr', 'insn', 'kind'])
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws54_mdmgr_startup_dispatch_init.md and .csv')


if __name__ == '__main__':
    main()

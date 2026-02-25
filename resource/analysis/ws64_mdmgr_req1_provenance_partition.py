#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

TARGET = Path('w31/extract/mdmgr.exe')
HANDLER = (0x0D31, 0x0EF7)  # second-stage dispatcher function window


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def main() -> None:
    raw = TARGET.read_bytes()
    hdr = u16(raw, 0x08) * 16
    img = raw[hdr:]

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(img, 0))

    rows = []
    for x in ins:
        o = x.op_str.lower().replace(' ', '')
        if 'es:[bx+1]' not in o:
            continue

        access = 'other'
        if x.mnemonic == 'mov' and o.startswith('byteptres:[bx+1],'):
            access = 'write'
        elif x.mnemonic in ('cmp', 'mov', 'test'):
            access = 'read'

        zone = 'handler_0d31' if HANDLER[0] <= x.address < HANDLER[1] else 'outside_handler'
        rows.append(
            {
                'addr': f'0x{x.address:04x}',
                'insn': f'{x.mnemonic} {x.op_str}',
                'access': access,
                'zone': zone,
            }
        )

    h_reads = [r for r in rows if r['zone'] == 'handler_0d31' and r['access'] == 'read']
    h_writes = [r for r in rows if r['zone'] == 'handler_0d31' and r['access'] == 'write']

    # Known guard-derived domain from WS62 path
    req1_domain = [9, 10, 11, 12, 13]

    md_lines = [
        '# WS64 mdmgr req[+1] Provenance Partition',
        '',
        'Date: 2026-02-17',
        '',
        '## Findings',
        f'- total `es:[bx+1]` touch points: {len(rows)}',
        f'- in handler window `0x0d31..0x0ef6`: reads={len(h_reads)}, writes={len(h_writes)}',
        '- handler touch points are read-only (`0x0d67`, `0x0d74`, `0x0e49`), supporting interpretation that `req[+1]` is input in this function.',
        f"- guard-derived second-dispatch domain remains `req[+1] in {req1_domain}`.",
        '- writes to `es:[bx+1]` are observed outside this handler (builder/formatter-style paths), and are not directly shown to dominate `0x0d31` input.',
        '- Conclusion: for second-dispatch analysis, `req[+1]` should be treated as externally supplied contract field at `0x0d31` entry.',
    ]

    Path('analysis/ws64_mdmgr_req1_provenance_partition.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws64_mdmgr_req1_provenance_partition.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['addr', 'insn', 'access', 'zone'])
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws64_mdmgr_req1_provenance_partition.md and .csv')


if __name__ == '__main__':
    main()

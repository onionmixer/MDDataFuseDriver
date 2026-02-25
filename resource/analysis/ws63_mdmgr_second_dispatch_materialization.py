#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

TARGET = Path('w31/extract/mdmgr.exe')
TABLE = 0x07DF
COUNT = 14


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def main() -> None:
    raw = TARGET.read_bytes()
    hdr = u16(raw, 0x08) * 16
    img = raw[hdr:]

    # MZ relocation linear offsets
    crlc = u16(raw, 0x06)
    lfarlc = u16(raw, 0x18)
    rels = set()
    for i in range(crlc):
        off, seg = struct.unpack_from('<HH', raw, lfarlc + i * 4)
        rels.add((seg << 4) + off)

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(img, 0))

    # direct static writes that mention 0x07df-window
    write_hits = []
    for x in ins:
        if x.mnemonic != 'mov':
            continue
        t = (x.mnemonic + ' ' + x.op_str).lower().replace(' ', '')
        if 'wordptr[0x7df]' in t or 'wordptr[0x7e' in t or 'wordptr[0x7f' in t:
            write_hits.append(x)

    rows = []
    vals = [u16(img, TABLE + i * 2) for i in range(COUNT)]
    for i, v in enumerate(vals):
        a = TABLE + i * 2
        rows.append(
            {
                'index': i,
                'table_off': f'0x{a:04x}',
                'target_off': f'0x{v:04x}',
                'target_in_image': 'yes' if v < len(img) else 'no',
                'table_word_reloc': 'yes' if a in rels else 'no',
            }
        )

    # second-dispatch reachable domain from code:
    # req1 > 8 (0x0d6c fallthrough), req1 <= 0x0d (0x0e51/0x0e54)
    domain = list(range(9, 14))
    dom_rows = [r for r in rows if r['index'] in domain]

    in_img = sum(1 for r in dom_rows if r['target_in_image'] == 'yes')

    md_lines = [
        '# WS63 mdmgr Second-dispatch Target Materialization',
        '',
        'Date: 2026-02-17',
        '',
        'Scope: jump table at `cs:[bx+0x07df]` used by `0x0e58`.',
        '',
        '## Findings',
        f'- table entries analyzed: {COUNT}',
        f'- direct static writes to `0x07df..0x07f9`: {len(write_hits)}',
        f'- relocation hits on table words: {sum(1 for r in rows if r["table_word_reloc"] == "yes")}',
        '- second-dispatch domain from guards: `req[+1] in {9,10,11,12,13}`.',
        f'- within that domain, targets inside current image: {in_img}/{len(dom_rows)}.',
        '- Interpretation: table is not statically materialized by observed writes/relocs; behavior depends on protocol-level reachable opcode subset in `req[+1]`.',
    ]

    md_lines.extend(['', '## Domain Entries (`req[+1]=9..13`)'])
    for r in dom_rows:
        md_lines.append(
            f"- idx {r['index']}: target {r['target_off']} (in_image={r['target_in_image']})"
        )

    Path('analysis/ws63_mdmgr_second_dispatch_materialization.md').write_text(
        '\n'.join(md_lines) + '\n', encoding='utf-8'
    )
    with open('analysis/ws63_mdmgr_second_dispatch_materialization.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['index', 'table_off', 'target_off', 'target_in_image', 'table_word_reloc'])
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws63_mdmgr_second_dispatch_materialization.md and .csv')


if __name__ == '__main__':
    main()

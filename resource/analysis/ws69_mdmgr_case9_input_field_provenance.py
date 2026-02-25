#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

TARGET = Path('w31/extract/mdmgr.exe')
CASE9_FIELDS = list(range(0x10, 0x18))


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def main() -> None:
    raw = TARGET.read_bytes()
    hdr = u16(raw, 0x08) * 16
    img = raw[hdr:]

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(img, 0))

    rows = []

    # Generic reads/writes touching es:[bx+off] for off in 0x10..0x17
    for off in CASE9_FIELDS:
        pat = f'es:[bx+0x{off:x}]'
        reads = []
        writes = []
        for x in ins:
            o = x.op_str.lower().replace(' ', '')
            if pat not in o:
                continue
            if x.mnemonic == 'mov' and o.startswith(f'byteptres:[bx+0x{off:x}],'):
                writes.append(x.address)
            else:
                reads.append(x.address)

        rows.append(
            {
                'field_off': f'0x{off:02x}',
                'reads': str(len(reads)),
                'writes': str(len(writes)),
                'read_sites': ','.join(f'0x{a:04x}' for a in reads[:12]),
                'write_sites': ','.join(f'0x{a:04x}' for a in writes[:12]),
                'note': 'global es:[bx+off] touch count',
            }
        )

    # Stronger check: writes to req-like base (les bx,[bp+6] immediately before write).
    req_writes = []
    for i, x in enumerate(ins):
        o = x.op_str.lower().replace(' ', '')
        if x.mnemonic != 'mov':
            continue
        m = re.match(r'byteptres:\[bx\+0x([0-9a-f]+)\],', o)
        if not m:
            continue
        off = int(m.group(1), 16)
        if off not in CASE9_FIELDS:
            continue
        # backward small window for les bx,[bp+6]
        hit = False
        for j in range(max(0, i - 4), i):
            y = ins[j]
            if y.mnemonic == 'les' and y.op_str.lower().replace(' ', '') == 'bx,ptr[bp+6]':
                hit = True
                break
        if hit:
            req_writes.append((x.address, off, f'{x.mnemonic} {x.op_str}'))

    # Case9 reader sites (fixed)
    case9_reads = [0x104a, 0x105b, 0x1069, 0x1077, 0x1085, 0x1093, 0x10a1, 0x10b1, 0x10bf, 0x10c6]

    md_lines = [
        '# WS69 mdmgr Case-9 Input Field Provenance',
        '',
        'Date: 2026-02-17',
        '',
        'Scope: `req[0x10..0x17]` consumed by case-9 path (`0x1047`).',
        '',
        '## Findings',
        f'- case-9 reader sites reviewed: {len(case9_reads)}',
        f'- req-like local writes to `es:[bx+0x10..0x17]` with immediate base pattern `les bx,[bp+6]`: {len(req_writes)}',
        '- In current bounded static pass, case-9 input fields are observed as read-mostly contract bytes.',
        '- Multiple helper mappers (`0x1205`, `0x1226`, `0x129b`) also read these offsets and emit transformed output buffers, reinforcing role as structured input lanes.',
        '- Interpretation: `0x1047` consumes pre-assembled request-extension fields rather than constructing them locally.',
    ]

    Path('analysis/ws69_mdmgr_case9_input_field_provenance.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws69_mdmgr_case9_input_field_provenance.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['field_off', 'reads', 'writes', 'read_sites', 'write_sites', 'note'])
        w.writeheader()
        w.writerows(rows)

    with open('analysis/ws69_mdmgr_case9_input_field_reqwrites.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['addr', 'off', 'insn'])
        for a, off, insn in req_writes:
            w.writerow([f'0x{a:04x}', f'0x{off:02x}', insn])

    print('wrote ws69 md/csv (+reqwrites csv)')


if __name__ == '__main__':
    main()

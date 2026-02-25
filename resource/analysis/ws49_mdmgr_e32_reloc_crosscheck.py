#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv

TARGET = Path('w31/extract/mdmgr.exe')
BASE = 0x0E32
ENTRIES = 3


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def main() -> None:
    b = TARGET.read_bytes()
    e_crlc = u16(b, 0x06)
    e_cparhdr = u16(b, 0x08)
    e_lfarlc = u16(b, 0x18)
    img_base = e_cparhdr * 16

    relocs = []
    reloc_locs = set()
    for i in range(e_crlc):
        off, seg = struct.unpack_from('<HH', b, e_lfarlc + i * 4)
        loc = seg * 16 + off
        relocs.append((i, off, seg, loc))
        reloc_locs.add(loc)

    rows = []
    for idx in range(ENTRIES):
        low = BASE + idx * 4
        high = low + 2
        init_low = u16(b, img_base + low)
        init_high = u16(b, img_base + high)
        rows.append(
            {
                'entry': idx,
                'low': f'0x{low:04x}',
                'high': f'0x{high:04x}',
                'init_low': f'0x{init_low:04x}',
                'init_high': f'0x{init_high:04x}',
                'low_reloc': 'yes' if low in reloc_locs else 'no',
                'high_reloc': 'yes' if high in reloc_locs else 'no',
            }
        )

    # also check parser callback slot 0x0c42/0x0c44 for comparison
    comp = []
    for low, high, name in [(0x0C42, 0x0C44, 'c42_pair'), (0x0CFA, 0x0CFC, 'cfa_pair'), (0x0CFE, 0x0D00, 'cfe_pair')]:
        comp.append(
            {
                'name': name,
                'low': f'0x{low:04x}',
                'high': f'0x{high:04x}',
                'low_reloc': 'yes' if low in reloc_locs else 'no',
                'high_reloc': 'yes' if high in reloc_locs else 'no',
            }
        )

    md_lines = [
        '# WS49 mdmgr 0x0e32 Relocation Crosscheck',
        '',
        'Date: 2026-02-17',
        '',
        f'- MZ relocation entries: `{e_crlc}`',
        f'- Relocation table offset: `0x{e_lfarlc:04x}`',
        f'- Image base (header paragraphs): `0x{img_base:04x}`',
        '',
        '## Dispatch Entry Relocation Status',
        '| entry | low | high | init_low | init_high | low_reloc | high_reloc |',
        '| --- | --- | --- | --- | --- | --- | --- |',
    ]

    for r in rows:
        md_lines.append(
            f"| {r['entry']} | {r['low']} | {r['high']} | {r['init_low']} | {r['init_high']} | {r['low_reloc']} | {r['high_reloc']} |"
        )

    md_lines.extend([
        '',
        '## Comparison Slots',
        '| name | low | high | low_reloc | high_reloc |',
        '| --- | --- | --- | --- | --- |',
    ])
    for r in comp:
        md_lines.append(f"| {r['name']} | {r['low']} | {r['high']} | {r['low_reloc']} | {r['high_reloc']} |")

    md_lines.extend([
        '',
        '## Conclusion',
        '- `0x0e32` table entry words are not relocation-marked in the MZ table.',
        '- Combined with WS48 (entry #1 explicit write, #0/#2 no literal writes), entry #0/#2 remain unresolved static constants from current image view.',
        '- This suggests provider closure for #0/#2 likely needs deeper runtime tracing or non-literal write path recovery, not simple MZ reloc explanation.',
    ])

    Path('analysis/ws49_mdmgr_e32_reloc_crosscheck.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws49_mdmgr_e32_reloc_crosscheck.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['entry', 'low', 'high', 'init_low', 'init_high', 'low_reloc', 'high_reloc'],
        )
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws49_mdmgr_e32_reloc_crosscheck.md and .csv')


if __name__ == '__main__':
    main()

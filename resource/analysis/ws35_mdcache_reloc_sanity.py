#!/usr/bin/env python3
from __future__ import annotations

import struct
from pathlib import Path


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def main() -> None:
    p = Path('w31/extract/mdcache.exe')
    b = p.read_bytes()
    hdr = u16(b, 0x08) * 16
    nrel = u16(b, 0x06)
    rel_off = u16(b, 0x18)

    # target cluster in file space
    lo, hi = 0x0D000, 0x0D140

    hits_method_a = []  # standard: relocation cell = hdr + seg*16 + off
    hits_method_b = []  # legacy ws6/ws7 style: seg_fix-2 indirection

    for i in range(nrel):
        ro = rel_off + i * 4
        if ro + 4 > len(b):
            break
        off, seg = struct.unpack_from('<HH', b, ro)

        cell_a = hdr + (seg << 4) + off
        if cell_a + 4 <= len(b):
            vo = u16(b, cell_a)
            vs = u16(b, cell_a + 2)
            tgt_a = hdr + (vs << 4) + vo
            if lo <= cell_a <= hi or lo <= tgt_a <= hi:
                hits_method_a.append((i, cell_a, tgt_a, vs, vo))

        seg_fix = hdr + (seg << 4) + off
        cell_b = seg_fix - 2
        if 0 <= cell_b and cell_b + 4 <= len(b):
            vo = u16(b, cell_b)
            vs = u16(b, cell_b + 2)
            tgt_b = hdr + (vs << 4) + vo
            if lo <= cell_b <= hi or lo <= tgt_b <= hi:
                hits_method_b.append((i, cell_b, tgt_b, vs, vo))

    md = [
        '# WS35 mdcache Relocation Sanity Check',
        '',
        'Date: 2026-02-17',
        '',
        f'- reloc_count: `{nrel}`',
        f'- header_bytes: `0x{hdr:04x}`',
        f'- cluster_range(file): `0x{lo:05x}..0x{hi:05x}`',
        '',
        '## Method A (standard MZ cell addressing)',
        f'- hits: `{len(hits_method_a)}`',
        '',
        '| rel# | cell_file_off | target_file_off | far(seg:off) |',
        '| --- | --- | --- | --- |',
    ]
    for i, c, t, s, o in hits_method_a[:40]:
        md.append(f'| {i} | 0x{c:05x} | 0x{t:05x} | {s:04x}:{o:04x} |')

    md.extend([
        '',
        '## Method B (legacy seg_fix-2 heuristic)',
        f'- hits: `{len(hits_method_b)}`',
        '',
        '| rel# | cell_file_off | target_file_off | far(seg:off) |',
        '| --- | --- | --- | --- |',
    ])
    for i, c, t, s, o in hits_method_b[:40]:
        md.append(f'| {i} | 0x{c:05x} | 0x{t:05x} | {s:04x}:{o:04x} |')

    md.extend([
        '',
        '## Conclusion',
        '- Relocation-to-blob evidence is method-sensitive in current scripts.',
        '- Keep token/descriptor contiguity as primary evidence; treat relocation linkage as lower-confidence until runtime-backed.',
    ])

    Path('analysis/ws35_mdcache_reloc_sanity.md').write_text('\n'.join(md) + '\n', encoding='utf-8')
    print('wrote analysis/ws35_mdcache_reloc_sanity.md')


if __name__ == '__main__':
    main()

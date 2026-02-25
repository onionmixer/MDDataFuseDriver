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


def linear(seg: int, off: int) -> int:
    return (seg << 4) + off


def main() -> None:
    raw = TARGET.read_bytes()
    hdr = u16(raw, 0x08) * 16
    img = raw[hdr:]
    img_len = len(img)

    rows = []
    for idx in range(ENTRIES):
        low = BASE + idx * 4
        high = low + 2
        off = u16(img, low)
        seg = u16(img, high)
        lin = linear(seg, off)
        rows.append(
            {
                'entry': idx,
                'slot_low': f'0x{low:04x}',
                'slot_high': f'0x{high:04x}',
                'offset': f'0x{off:04x}',
                'segment': f'0x{seg:04x}',
                'linear': f'0x{lin:05x}',
                'in_image': 'yes' if 0 <= lin < img_len else 'no',
                'image_len': f'0x{img_len:04x}',
            }
        )

    # entry #1 code re-init seen in WS48: [0xe36]=0x095c, [0xe38]=0x011f
    off1_runtime = 0x095C
    seg1_runtime = 0x011F
    lin1_runtime = linear(seg1_runtime, off1_runtime)

    md_lines = [
        '# WS52 mdmgr 0x0e32 Far-pointer Classification',
        '',
        'Date: 2026-02-17',
        '',
        f'- image length (post-MZ-header): `0x{img_len:04x}`',
        '',
        '## Initial Entry Values (`offset:segment`)',
        '| entry | low | high | offset | segment | linear | in_image |',
        '| --- | --- | --- | --- | --- | --- | --- |',
    ]

    for r in rows:
        md_lines.append(
            f"| {r['entry']} | {r['slot_low']} | {r['slot_high']} | {r['offset']} | {r['segment']} | {r['linear']} | {r['in_image']} |"
        )

    md_lines.extend([
        '',
        '## Entry #1 Re-init (from WS48 writes)',
        f'- code writes: `[0x0e36]=0x{off1_runtime:04x}`, `[0x0e38]=0x{seg1_runtime:04x}`',
        f'- interpreted far pointer: `{seg1_runtime:04x}:{off1_runtime:04x}` (linear `0x{lin1_runtime:05x}`)',
        f"- in-image after re-init: {'yes' if lin1_runtime < img_len else 'no'}",
        '',
        '## Conclusion',
        '- Dispatch entries are true far pointers (`lcall m16:16`), not near offsets.',
        '- Initial entry #0 and #2 point outside current image address space, consistent with external/resident target stubs.',
        '- Entry #1 is rewritten to an in-image handler pointer by code, matching observed explicit writes.',
    ])

    Path('analysis/ws52_mdmgr_e32_farptr_classification.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws52_mdmgr_e32_farptr_classification.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['entry', 'slot_low', 'slot_high', 'offset', 'segment', 'linear', 'in_image', 'image_len'],
        )
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws52_mdmgr_e32_farptr_classification.md and .csv')


if __name__ == '__main__':
    main()

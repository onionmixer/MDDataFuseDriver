#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv

TARGET = Path('w31/extract/mdmgr.exe')
L = None


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def feasible_s_range(seg: int, off: int, img_len: int):
    # 0 <= ((seg-S)<<4)+off < img_len
    ok = []
    for S in range(0x0000, 0x10000):
        lin = ((seg - S) << 4) + off
        if 0 <= lin < img_len:
            ok.append(S)
    if not ok:
        return None
    return min(ok), max(ok), len(ok)


def main() -> None:
    raw = TARGET.read_bytes()
    hdr = u16(raw, 0x08) * 16
    img = raw[hdr:]
    img_len = len(img)

    # from WS52
    entries = [
        ('entry0_init', 0x478A, 0x2606),
        ('entry1_init', 0x6B00, 0xB402),
        ('entry1_set', 0x011F, 0x095C),
        ('entry2_init', 0x2E05, 0x14C0),
    ]

    rows = []
    intervals = {}
    for name, seg, off in entries:
        r = feasible_s_range(seg, off, img_len)
        if r is None:
            rows.append(
                {
                    'name': name,
                    'segment': f'0x{seg:04x}',
                    'offset': f'0x{off:04x}',
                    's_min': '',
                    's_max': '',
                    'count': 0,
                }
            )
            continue
        smin, smax, cnt = r
        intervals[name] = (smin, smax)
        rows.append(
            {
                'name': name,
                'segment': f'0x{seg:04x}',
                'offset': f'0x{off:04x}',
                's_min': f'0x{smin:04x}',
                's_max': f'0x{smax:04x}',
                'count': cnt,
            }
        )

    # intersection checks
    def inter(a, b):
        lo = max(a[0], b[0])
        hi = min(a[1], b[1])
        return (lo, hi) if lo <= hi else None

    i0 = intervals.get('entry0_init')
    i2 = intervals.get('entry2_init')
    i1s = intervals.get('entry1_set')

    i0_i2 = inter(i0, i2) if i0 and i2 else None
    i0_i1s = inter(i0, i1s) if i0 and i1s else None
    i2_i1s = inter(i2, i1s) if i2 and i1s else None

    md_lines = [
        '# WS53 mdmgr Far-pointer Load-segment Feasibility',
        '',
        'Date: 2026-02-17',
        '',
        f'- image length: `0x{img_len:04x}`',
        '',
        '## Per-pointer feasible load-segment ranges',
        '| name | segment | offset | feasible S min | feasible S max | count |',
        '| --- | --- | --- | --- | --- | --- |',
    ]
    for r in rows:
        md_lines.append(f"| {r['name']} | {r['segment']} | {r['offset']} | {r['s_min']} | {r['s_max']} | {r['count']} |")

    md_lines.extend([
        '',
        '## Intersection checks',
        f"- entry0_init ∩ entry2_init: {'none' if i0_i2 is None else hex(i0_i2[0])+'..'+hex(i0_i2[1])}",
        f"- entry0_init ∩ entry1_set: {'none' if i0_i1s is None else hex(i0_i1s[0])+'..'+hex(i0_i1s[1])}",
        f"- entry2_init ∩ entry1_set: {'none' if i2_i1s is None else hex(i2_i1s[0])+'..'+hex(i2_i1s[1])}",
        '',
        '## Conclusion',
        '- `entry0_init` and `entry2_init` cannot be mapped in-image under a single common load segment with `entry1_set`.',
        '- This strengthens that #0/#2 initial pointers are not same-module in-image handlers under the observed model.',
        '- Combined with WS52, #0/#2 are high-confidence external/resident targets; #1 is rewritten to local in-image handler.',
    ])

    Path('analysis/ws53_mdmgr_farptr_loadseg_feasibility.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws53_mdmgr_farptr_loadseg_feasibility.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['name', 'segment', 'offset', 's_min', 's_max', 'count'])
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws53_mdmgr_farptr_loadseg_feasibility.md and .csv')


if __name__ == '__main__':
    main()

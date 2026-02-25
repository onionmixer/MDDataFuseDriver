#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv

TARGET = Path('w31/extract/mdmgr.exe')


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def pair(img: bytes, low: int) -> tuple[int, int]:
    return u16(img, low), u16(img, low + 2)


def main() -> None:
    raw = TARGET.read_bytes()
    hdr = u16(raw, 0x08) * 16
    img = raw[hdr:]

    rows = []

    # Phase 0: raw image defaults
    r0 = [pair(img, 0x0e32), pair(img, 0x0e36), pair(img, 0x0e3a)]
    rows.append({'phase': 'raw_image', 'entry0': f'{r0[0][1]:04x}:{r0[0][0]:04x}', 'entry1': f'{r0[1][1]:04x}:{r0[1][0]:04x}', 'entry2': f'{r0[2][1]:04x}:{r0[2][0]:04x}', 'evidence': 'on-disk words'})

    # Phase 1: startup zero loop then set entry0 default (WS54)
    rows.append({'phase': 'startup_zero_loop', 'entry0': '0000:0000', 'entry1': '0000:0000', 'entry2': '0000:0000', 'evidence': '0x2e7f/0x2e85 over i=0..7'})
    rows.append({'phase': 'startup_set_entry0', 'entry0': '0073:0601', 'entry1': '0000:0000', 'entry2': '0000:0000', 'evidence': '0x2ed8/0x2ede and 0x2efa/0x2f00'})

    # Phase 2: optional later rebind observed elsewhere
    rows.append({'phase': 'runtime_rebind_entry1_observed', 'entry0': '0073:0601(?)', 'entry1': '011f:095c', 'entry2': '0000:0000(?)', 'evidence': '0x19d5/0x19db writes; ordering vs startup unresolved statically'})

    md_lines = [
        '# WS55 mdmgr 0x0e32 Dispatch State Timeline',
        '',
        'Date: 2026-02-17',
        '',
        '| phase | entry0 | entry1 | entry2 | evidence |',
        '| --- | --- | --- | --- | --- |',
    ]
    for r in rows:
        md_lines.append(f"| {r['phase']} | {r['entry0']} | {r['entry1']} | {r['entry2']} | {r['evidence']} |")

    md_lines.extend([
        '',
        '## Interpretation',
        '- Runtime baseline immediately after startup init is `entry0=0073:0601`, `entry1=0`, `entry2=0`.',
        '- Entry #1 in-image pointer (`011f:095c`) is observed as explicit write in another code path, but static ordering relative to startup path remains unresolved.',
        '- Entry #2 provider remains unresolved; no direct/non-literal static write found in current bounded passes.',
    ])

    Path('analysis/ws55_mdmgr_e32_state_timeline.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws55_mdmgr_e32_state_timeline.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['phase', 'entry0', 'entry1', 'entry2', 'evidence'])
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws55_mdmgr_e32_state_timeline.md and .csv')


if __name__ == '__main__':
    main()

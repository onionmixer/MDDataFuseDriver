#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv

TARGET = Path('w31/extract/mdmgr.exe')
WANT = 0x1997


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def main() -> None:
    raw = TARGET.read_bytes()
    hdr = u16(raw, 0x08) * 16
    img = raw[hdr:]

    rows: list[dict[str, str]] = []

    # A) runtime-loaded external far pointer slot (WS46/WS47)
    rows.append({
        'family': 'external_loaded_farptr',
        'site': 'lcall [0x0c42] @ 0x0398/0x0501/0x0573/0x0684',
        'model': 'runtime file-read loaded (int21/4402, 4 bytes)',
        'candidate_offsets': 'unknown',
        'can_be_1997': 'unknown',
        'priority': 'high',
        'reason': 'only unresolved externally supplied far pointer lane',
    })

    # B) indexed dispatch table 0x0e32 (WS54/WS55 runtime model)
    e32_entries = [(0, 0x0601, 0x0073), (1, 0x095C, 0x011F), (2, 0x0000, 0x0000)]
    e32_offs = {lo for _, lo, _ in e32_entries}
    rows.append({
        'family': 'indexed_dispatch_e32',
        'site': 'lcall [bx+0x0e32] / lcall [0x0e32]',
        'model': 'WS55 runtime timeline entries 0..2',
        'candidate_offsets': ','.join(f'0x{x:04x}' for x in sorted(e32_offs)),
        'can_be_1997': 'yes' if WANT in e32_offs else 'no',
        'priority': 'low',
        'reason': 'runtime entries resolved; 0x1997 absent',
    })

    # C) indexed helper table 0x0d02 (WS54 startup init model)
    # startup: 8 entries zeroed then entry#1 set to 011f:095c
    d02_offs = {0x0000, 0x095C}
    rows.append({
        'family': 'indexed_helper_d02',
        'site': 'lcall [bx+0x0d02] @ 0x0ee5',
        'model': 'startup-zero(8 entries) + entry1=011f:095c',
        'candidate_offsets': ','.join(f'0x{x:04x}' for x in sorted(d02_offs)),
        'can_be_1997': 'yes' if WANT in d02_offs else 'no',
        'priority': 'low',
        'reason': 'startup model excludes 0x1997',
    })

    # D) stride-0x11 dynamic lanes used by [bx+0xdcf/dd3/dd7/ddb]
    # One path has explicit guard idx<3: bx = idx*0x11 at 0x07f5.
    # Capture raw image candidate offsets for that bounded path to prioritize runtime work.
    for base in (0x0DCF, 0x0DD3, 0x0DD7, 0x0DDB):
        offs = []
        for idx in range(3):
            o = base + idx * 0x11
            if o + 1 >= len(img):
                continue
            offs.append(u16(img, o))
        can = WANT in offs
        rows.append({
            'family': 'stride11_dynamic_lane',
            'site': f'lcall [bx+0x{base:04x}] (bounded path idx<3 observed)',
            'model': 'raw-image bounded sample (idx=0..2); runtime writes partially known',
            'candidate_offsets': ','.join(f'0x{x:04x}' for x in offs),
            'can_be_1997': 'yes' if can else 'unknown',
            'priority': 'medium',
            'reason': 'index and table values are runtime-sensitive in other paths',
        })

    yes_n = sum(1 for r in rows if r['can_be_1997'] == 'yes')
    no_n = sum(1 for r in rows if r['can_be_1997'] == 'no')
    unk_n = sum(1 for r in rows if r['can_be_1997'] == 'unknown')

    md = [
        '# WS58 mdmgr Dynamic Vector Prioritization vs 0x1997',
        '',
        'Date: 2026-02-17',
        '',
        '## Outcome',
        f'- families analyzed: {len(rows)}',
        f'- can_be_1997=yes: {yes_n}',
        f'- can_be_1997=no: {no_n}',
        f'- can_be_1997=unknown: {unk_n}',
        '- Highest-priority remaining branch source is external-loaded far pointer slot `0x0c42`.',
        '- Runtime models for `0x0e32` and `0x0d02` exclude offset `0x1997`.',
        '',
        '## Priority Order',
        '1. `0x0c42` runtime load provenance/value capture',
        '2. stride-`0x11` dynamic lanes (`0x0dcf/0x0dd3/0x0dd7/0x0ddb`) with runtime index/value capture',
        '3. no immediate action required for resolved runtime tables (`0x0e32`, `0x0d02`) regarding `0x1997`',
    ]

    Path('analysis/ws58_mdmgr_dynamic_vector_prioritization.md').write_text('\n'.join(md) + '\n', encoding='utf-8')
    with open('analysis/ws58_mdmgr_dynamic_vector_prioritization.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['family', 'site', 'model', 'candidate_offsets', 'can_be_1997', 'priority', 'reason'],
        )
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws58_mdmgr_dynamic_vector_prioritization.md and .csv')


if __name__ == '__main__':
    main()

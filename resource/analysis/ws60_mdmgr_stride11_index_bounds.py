#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv

TARGET = Path('w31/extract/mdmgr.exe')
WANT = 0x1997


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def apply_u16(buf: bytearray, o: int, v: int) -> None:
    struct.pack_into('<H', buf, o, v & 0xFFFF)


def main() -> None:
    raw = TARGET.read_bytes()
    hdr = u16(raw, 0x08) * 16
    img = raw[hdr:]

    # post-init overlay model from explicit init writes around 0x0bc0..0x0d20 (WS54 context)
    post = bytearray(img)
    writes = {
        0x0DCF: 0x0002,
        0x0DD1: 0x0073,
        0x0DD3: 0x04A5,
        0x0DD5: 0x0024,
        0x0DD7: 0x040C,
        0x0DD9: 0x0024,
        0x0DDB: 0x04DD,
        0x0DDD: 0x0024,
    }
    for a, v in writes.items():
        if a + 1 < len(post):
            apply_u16(post, a, v)

    rows: list[dict[str, str]] = []

    # Three callsites with explicit idx<3 guards.
    guarded = [
        ('0x07fa lcall [bx+0x0dcf]', 0x0DCF),
        ('0x0879 lcall [bx+0x0dd7]', 0x0DD7),
        ('0x08e1 lcall [bx+0x0dd3]', 0x0DD3),
    ]

    for label, base in guarded:
        addrs = [base + i * 0x11 for i in range(3)]
        raw_offs = []
        post_offs = []
        for a in addrs:
            raw_offs.append(u16(img, a) if a + 1 < len(img) else None)
            post_offs.append(u16(post, a) if a + 1 < len(post) else None)

        rows.append({
            'site': label,
            'idx_model': 'explicit_guard: idx in {0,1,2}',
            'slot_addrs': ','.join(f'0x{x:04x}' for x in addrs),
            'raw_offsets': ','.join('n/a' if v is None else f'0x{v:04x}' for v in raw_offs),
            'postinit_offsets': ','.join('n/a' if v is None else f'0x{v:04x}' for v in post_offs),
            'contains_1997_raw': 'yes' if WANT in {v for v in raw_offs if v is not None} else 'no',
            'contains_1997_postinit': 'yes' if WANT in {v for v in post_offs if v is not None} else 'no',
            'note': 'bounded stride-0x11 lane',
        })

    # 0x0916 path: idx_src = req[+2] -> k; al = [0x0d30 + k*0x14]; bx = signext(al)*0x11
    # Startup init writes [0x0d30 + i*0x14] = 0xFF for i=0..7.
    k_bounded = list(range(8))
    table_vals = [0xFF for _ in k_bounded]
    bx_vals = [((v if v < 0x80 else v - 0x100) * 0x11) & 0xFFFF for v in table_vals]
    lane_addrs = [((0x0DDB + bx) & 0xFFFF) for bx in bx_vals]
    raw_offs = [u16(img, a) if a + 1 < len(img) else None for a in lane_addrs]
    post_offs = [u16(post, a) if a + 1 < len(post) else None for a in lane_addrs]

    rows.append({
        'site': '0x0916 lcall [bx+0x0ddb]',
        'idx_model': 'k=req[+2] unbounded here; if k<8 then table byte forced to 0xFF by init',
        'slot_addrs': ','.join(sorted({f'0x{x:04x}' for x in lane_addrs})),
        'raw_offsets': ','.join(sorted({f'0x{v:04x}' for v in raw_offs if v is not None})),
        'postinit_offsets': ','.join(sorted({f'0x{v:04x}' for v in post_offs if v is not None})),
        'contains_1997_raw': 'yes' if WANT in {v for v in raw_offs if v is not None} else 'no',
        'contains_1997_postinit': 'yes' if WANT in {v for v in post_offs if v is not None} else 'no',
        'note': 'for k>=8 behavior remains dynamic/unresolved in this pass',
    })

    yes_raw = sum(1 for r in rows if r['contains_1997_raw'] == 'yes')
    yes_post = sum(1 for r in rows if r['contains_1997_postinit'] == 'yes')

    md = [
        '# WS60 mdmgr stride-0x11 Index-Bounds Consolidation',
        '',
        'Date: 2026-02-17',
        '',
        '## Results',
        f'- analyzed lanes: {len(rows)}',
        f'- contains `0x1997` in raw model: {yes_raw}',
        f'- contains `0x1997` in post-init model: {yes_post}',
        '- Three stride-`0x11` consumers (`0x07fa`, `0x0879`, `0x08e1`) have explicit `idx<3` guards.',
        '- `0x0916` consumes remapped index via `[0x0d30 + k*0x14]`; init writes force `0xFF` for `k=0..7`, folding to one lane address (`0x0dca`) in that bounded subspace.',
        '- Remaining uncertainty is concentrated on `0x0916` path for `k>=8` (no local bound in this function).',
    ]

    Path('analysis/ws60_mdmgr_stride11_index_bounds.md').write_text('\n'.join(md) + '\n', encoding='utf-8')
    with open('analysis/ws60_mdmgr_stride11_index_bounds.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                'site',
                'idx_model',
                'slot_addrs',
                'raw_offsets',
                'postinit_offsets',
                'contains_1997_raw',
                'contains_1997_postinit',
                'note',
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws60_mdmgr_stride11_index_bounds.md and .csv')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def u32(b: bytes, o: int) -> int:
    return struct.unpack_from('<I', b, o)[0]


def parse_mz_relocs(b: bytes):
    cnt = u16(b, 0x06)
    off = u16(b, 0x18)
    hdr = u16(b, 0x08) * 16
    out = []
    for i in range(cnt):
        roff = off + i * 4
        if roff + 4 > len(b):
            break
        ent_off = u16(b, roff)
        ent_seg = u16(b, roff + 2)
        # relocation cells are addressed in load module space (post-header)
        file_off = hdr + (ent_seg << 4) + ent_off
        out.append((i, file_off, ent_seg, ent_off))
    return out


def main() -> None:
    p = Path('w31/extract/mdcache.exe')
    b = p.read_bytes()
    hdr = u16(b, 0x08) * 16

    # Known from prior analyses (file offsets)
    blob_off = 0x0D052
    desc_base = 0x0D0AC
    rec0 = 0x0D0BA
    rec_stride = 0x14
    rec_count = 5

    # parse token strings in blob region
    token_region = b[blob_off:blob_off + 0x80]
    toks = []
    cur = []
    for x in token_region:
        if x == 0:
            if cur:
                s = bytes(cur).decode('latin1', 'replace')
                toks.append(s)
                cur = []
        else:
            cur.append(x)

    # keep only parser-relevant visible tokens in order
    keep = [t for t in toks if t in (':\\mdctl', 'ON', 'OFF', 'IS', 'FLUSH', '?', 'ERROR:')]

    # decode descriptor tuples
    recs = []
    for i in range(rec_count):
        ro = rec0 + i * rec_stride
        d0 = u32(b, ro)
        op = d0 & 0xFFFF
        idx = (d0 >> 16) & 0xFFFF
        handler = u32(b, ro + 0x10) & 0xFFFF
        recs.append((i, ro, op, idx, handler))

    # relocation entries that target around blob/desc region
    rel_hits = []
    for ridx, foff, seg, off in parse_mz_relocs(b):
        if foff + 4 > len(b):
            continue
        val_off = u16(b, foff)
        val_seg = u16(b, foff + 2)
        target = (val_seg << 4) + val_off
        if 0x0D000 <= target <= 0x0D120:
            rel_hits.append((ridx, foff, target, val_seg, val_off))

    md = [
        '# WS34 mdcache Blob/Descriptor Cluster',
        '',
        'Date: 2026-02-17',
        '',
        '## Layout (file offsets)',
        f'- token blob start: `0x{blob_off:05x}`',
        f'- descriptor base: `0x{desc_base:05x}`',
        f'- first record: `0x{rec0:05x}` (`count={rec_count}`, `stride=0x{rec_stride:x}`)',
        '',
        '## Token order in cluster',
        '- ' + ' -> '.join(keep),
        '',
        '## Descriptor tuples',
        '',
        '| rec_idx | rec_off | op_code | op_index | handler16 |',
        '| --- | --- | --- | --- | --- |',
    ]
    for i, ro, op, idx, h in recs:
        md.append(f'| {i} | 0x{ro:05x} | 0x{op:04x} | {idx} | 0x{h:04x} |')

    md.extend([
        '',
        '## Relocation hits into cluster region',
        '',
        '| rel# | ptr_cell_file_off | target_file_off | target_seg | target_off |',
        '| --- | --- | --- | --- | --- |',
    ])
    for ridx, foff, tgt, seg, off in rel_hits:
        md.append(f'| {ridx} | 0x{foff:05x} | 0x{tgt:05x} | 0x{seg:04x} | 0x{off:04x} |')

    md.extend([
        '',
        '## Interpretation',
        '- Token strings and 5-record descriptor table are contiguous in one data cluster.',
        '- Descriptor order and token order are structurally compatible, but instruction-level dispatch proof is still pending.',
        '- This supports WS33 as bounded low-confidence crosswalk evidence.',
    ])

    Path('analysis/ws34_mdcache_blob_cluster.md').write_text('\n'.join(md) + '\n', encoding='utf-8')
    with open('analysis/ws34_mdcache_blob_cluster.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['rec_idx', 'rec_off', 'op_code', 'op_index', 'handler16'],
        )
        w.writeheader()
        for i, ro, op, idx, h in recs:
            w.writerow(
                {
                    'rec_idx': i,
                    'rec_off': f'0x{ro:05x}',
                    'op_code': f'0x{op:04x}',
                    'op_index': idx,
                    'handler16': f'0x{h:04x}',
                }
            )

    print('wrote analysis/ws34_mdcache_blob_cluster.md and .csv')


if __name__ == '__main__':
    main()

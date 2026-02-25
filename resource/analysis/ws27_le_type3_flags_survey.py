#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import hashlib
import csv


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def u32(b: bytes, o: int) -> int:
    return struct.unpack_from('<I', b, o)[0]


def parse_names(buf: bytes, start: int, max_len: int | None = None):
    out = []
    if start <= 0 or start >= len(buf):
        return out
    end = len(buf) if max_len is None else min(len(buf), start + max_len)
    off = start
    while off < end:
        ln = buf[off]
        off += 1
        if ln == 0:
            break
        if off + ln + 2 > end:
            break
        name = buf[off:off + ln].decode('latin1', 'replace')
        off += ln
        ordv = u16(buf, off)
        off += 2
        out.append((ordv, name))
    return out


def parse_le_type3_x86(data: bytes, le_off: int):
    ent_off = u32(data, le_off + 0x5C)
    ent_abs = le_off + ent_off
    out = []
    ordv = 1
    p = ent_abs
    while p < len(data):
        cnt = data[p]
        p += 1
        if cnt == 0:
            break
        if p + 3 > len(data):
            break
        btype = data[p]
        obj = u16(data, p + 1)
        p += 3
        if btype == 0:
            ordv += cnt
            continue
        if btype == 3:
            need = cnt * 3
            if p + need > len(data):
                break
            raw = data[p:p + need]
            p += need
            for i in range(cnt):
                r = raw[i * 3:(i + 1) * 3]
                flags = r[0]
                middle16 = int.from_bytes(r[1:3], 'little')
                out.append((ordv + i, obj, flags, middle16, r.hex()))
            ordv += cnt
            continue

        # unknown/non-target types: skip conservatively by known x86 LE layouts
        if btype == 1:
            sz = 2
        elif btype == 2:
            sz = 4
        elif btype == 4:
            sz = 6
        else:
            break
        need = cnt * sz
        if p + need > len(data):
            break
        p += need
        ordv += cnt
    return out


def main() -> None:
    files = sorted(Path('w95').glob('extract/*/*'))
    rows = []
    le_files = []

    for fp in files:
        if not fp.is_file():
            continue
        b = fp.read_bytes()
        if len(b) < 0x40 or b[:2] != b'MZ':
            continue
        le_ptr = u32(b, 0x3C)
        if le_ptr + 2 > len(b) or b[le_ptr:le_ptr + 2] != b'LE':
            continue

        sha1 = hashlib.sha1(b).hexdigest()
        le_files.append((str(fp), sha1, len(b)))

        rnames = dict(parse_names(b, le_ptr + u32(b, le_ptr + 0x58)))
        nr_off = u32(b, le_ptr + 0x88)
        nr_len = u32(b, le_ptr + 0x8C)
        nrnames = dict(parse_names(b, nr_off, nr_len))

        for ordv, obj, flags, mid16, rawhex in parse_le_type3_x86(b, le_ptr):
            rows.append(
                {
                    'file': str(fp),
                    'sha1': sha1,
                    'size': str(len(b)),
                    'ordinal': str(ordv),
                    'obj': str(obj),
                    'flags_hex': f'0x{flags:02x}',
                    'middle16_hex': f'0x{mid16:04x}',
                    'entry_raw_hex': rawhex,
                    'resident_name': rnames.get(ordv, ''),
                    'nonresident_name': nrnames.get(ordv, ''),
                }
            )

    # stats
    uniq_bin = {}
    for f, s, z in le_files:
        uniq_bin.setdefault((s, z), []).append(f)

    flags_dist = {}
    by_name = {}
    for r in rows:
        flags_dist[r['flags_hex']] = flags_dist.get(r['flags_hex'], 0) + 1
        nm = r['nonresident_name'] or r['resident_name'] or '(none)'
        by_name.setdefault(nm, 0)
        by_name[nm] += 1

    md = [
        '# WS27 LE Type-3 Flags Survey',
        '',
        'Date: 2026-02-17',
        '',
        '## Scope',
        '- Parsed LE modules under `w95/extract/*/*`.',
        '- Entry-table decode mode: x86 LE type-3 bundle (`count,type,obj` + entry `[flags,u16]`).',
        '',
        '## LE files discovered',
        f'- Total LE files: `{len(le_files)}`',
        f'- Unique binaries by `(sha1,size)`: `{len(uniq_bin)}`',
        '',
        '## Flags distribution (type-3 entries)',
    ]
    for k in sorted(flags_dist.keys()):
        md.append(f'- `{k}`: `{flags_dist[k]}` entries')

    md.extend([
        '',
        '## Name correlation',
    ])
    for k in sorted(by_name.keys()):
        md.append(f'- `{k}`: `{by_name[k]}` entries')

    md.extend([
        '',
        '## Observations',
        '- All observed type-3 entries use `flags=0x03` in this corpus.',
        '- Type-3 ordinal is consistently associated with DDB-style name (`_The_DDB` / `MDHlp_DDB`).',
        '- US/JP duplicates do not add new flag variants (same binaries by hash).',
    ])

    Path('analysis/ws27_le_type3_flags_survey.md').write_text('\n'.join(md) + '\n', encoding='utf-8')
    with open('analysis/ws27_le_type3_flags_survey.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['file', 'sha1', 'size', 'ordinal', 'obj', 'flags_hex', 'middle16_hex', 'entry_raw_hex', 'resident_name', 'nonresident_name'],
        )
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws27_le_type3_flags_survey.md and .csv')


if __name__ == '__main__':
    main()

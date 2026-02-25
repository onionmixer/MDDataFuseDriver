#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import re
import csv

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

G_LO = 0x5B40
G_HI = 0x5B88


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def main() -> None:
    p = Path('w31/extract/mdfsck.exe')
    b = p.read_bytes()
    hdr = u16(b, 0x08) * 16
    code = b[hdr:]

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(code, 0))

    rows = []
    for i, x in enumerate(ins):
        s = f"{x.mnemonic} {x.op_str}".lower()
        ms = re.findall(r"\[0x([0-9a-f]{4})\]", s)
        if not ms:
            continue
        for m in ms:
            a = int(m, 16)
            if not (G_LO <= a <= G_HI):
                continue
            # collect tiny context window
            w = ins[max(0, i - 2): min(len(ins), i + 3)]
            ctx = ' || '.join([f"0x{q.address:04x}:{q.mnemonic} {q.op_str}" for q in w])
            rows.append(
                {
                    'ins_addr': f"0x{x.address:04x}",
                    'mnemonic': x.mnemonic,
                    'op_str': x.op_str,
                    'global_off': f"0x{a:04x}",
                    'context': ctx,
                }
            )

    # summarize by global
    byg: dict[str, list[dict[str, str]]] = {}
    for r in rows:
        byg.setdefault(r['global_off'], []).append(r)

    md_lines = [
        '# WS36 mdfsck Global Lane Xrefs',
        '',
        'Date: 2026-02-17',
        '',
        f'Target global range: `0x{G_LO:04x}..0x{G_HI:04x}`.',
        '',
        '## Summary by global word',
        '',
        '| global_off | xref_count | first_xrefs |',
        '| --- | --- | --- |',
    ]

    for g in sorted(byg.keys()):
        xs = byg[g]
        first = ', '.join(r['ins_addr'] for r in xs[:6])
        md_lines.append(f"| {g} | {len(xs)} | {first} |")

    md_lines.extend([
        '',
        '## Notable contiguous access clusters',
        '',
    ])

    # heuristic clusters: sequences where instruction references rising 5bxx offsets
    sorted_rows = sorted(rows, key=lambda r: int(r['ins_addr'], 16))
    cluster = []
    clusters = []
    prev_addr = None
    for r in sorted_rows:
        a = int(r['ins_addr'], 16)
        go = int(r['global_off'], 16)
        if not cluster:
            cluster = [(a, go, r)]
        else:
            pa, pg, _ = cluster[-1]
            if a - pa <= 0x10 and abs(go - pg) <= 0x10:
                cluster.append((a, go, r))
            else:
                if len(cluster) >= 4:
                    clusters.append(cluster)
                cluster = [(a, go, r)]
        prev_addr = a
    if cluster and len(cluster) >= 4:
        clusters.append(cluster)

    if not clusters:
        md_lines.append('- no dense contiguous clusters found by heuristic.')
    else:
        for c in clusters[:20]:
            start = c[0][0]
            end = c[-1][0]
            gos = ','.join(sorted({f"0x{x[1]:04x}" for x in c}))
            md_lines.append(f"- cluster `0x{start:04x}..0x{end:04x}` globals `{gos}`")

    md_lines.extend([
        '',
        '## Notes',
        '- This pass enumerates direct absolute-memory references only.',
        '- It helps identify where lane values are populated/consumed, but not media offsets by itself.',
    ])

    Path('analysis/ws36_mdfsck_global_lane_xrefs.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws36_mdfsck_global_lane_xrefs.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['ins_addr', 'mnemonic', 'op_str', 'global_off', 'context'])
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws36_mdfsck_global_lane_xrefs.md and .csv')


if __name__ == '__main__':
    main()

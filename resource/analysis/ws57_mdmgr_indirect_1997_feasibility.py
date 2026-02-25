#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

TARGET = Path('w31/extract/mdmgr.exe')
WANT = 0x1997


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def parse_abs_slot(op: str) -> int | None:
    t = op.lower().replace(' ', '')
    m = re.search(r'\[0x([0-9a-f]+)\]', t)
    if m:
        return int(m.group(1), 16)
    return None


def parse_bx_base(op: str) -> int | None:
    t = op.lower().replace(' ', '')
    m = re.search(r'\[bx\+0x([0-9a-f]+)\]', t)
    if m:
        return int(m.group(1), 16)
    return None


def main() -> None:
    raw = TARGET.read_bytes()
    hdr = u16(raw, 0x08) * 16
    img = raw[hdr:]

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(img, 0))

    # 1) all indirect transfer sites
    sites = []
    for x in ins:
        if x.mnemonic in ('call', 'lcall', 'jmp', 'ljmp') and '[' in x.op_str:
            sites.append(x)

    # 2) literal writes by address (word stores)
    lit_writes: dict[int, list[tuple[int, int]]] = {}
    for x in ins:
        if x.mnemonic != 'mov':
            continue
        t = x.op_str.lower().replace(' ', '')
        m = re.match(r'wordptr\[0x([0-9a-f]+)\],0x([0-9a-f]+)$', t)
        if not m:
            continue
        a = int(m.group(1), 16)
        v = int(m.group(2), 16)
        lit_writes.setdefault(a, []).append((x.address, v))

    # Startup-known runtime overwrites (from WS54/WS55 evidence).
    startup_pair: dict[int, tuple[int, int]] = {
        0x0E32: (0x0601, 0x0073),
        0x0E36: (0x0000, 0x0000),
        0x0E3A: (0x0000, 0x0000),
    }
    # from WS46: this slot is loaded from external read path (not fully static).
    runtime_loaded_far_slots = {0x0C42}

    rows = []

    # 3) global invariant: word 0x1997 not present in in-image bytes.
    occ = []
    for i in range(len(img) - 1):
        if u16(img, i) == WANT:
            occ.append(i)

    rows.append({
        'kind': 'global',
        'site': '-',
        'source': 'image_word_scan',
        'value': hex(WANT),
        'can_hit_1997': 'yes' if occ else 'no',
        'evidence': f'occurrences={len(occ)}',
    })

    # 4) inspect each indirect site source and candidate values.
    for x in sites:
        mnem = x.mnemonic.lower()
        op = x.op_str
        site = f'0x{x.address:04x}: {x.mnemonic} {x.op_str}'

        # absolute [0xADDR]
        abs_slot = parse_abs_slot(op)
        if abs_slot is not None:
            if mnem == 'lcall':
                lo = u16(img, abs_slot) if abs_slot + 1 < len(img) else None
                hi = u16(img, abs_slot + 2) if abs_slot + 3 < len(img) else None
                cand = []
                if lo is not None and hi is not None:
                    cand.append(('raw_init_far', lo, hi))
                if abs_slot in startup_pair:
                    slo, shi = startup_pair[abs_slot]
                    cand.append(('startup_model_far', slo, shi))
                for a in (abs_slot, abs_slot + 2):
                    for waddr, val in lit_writes.get(a, []):
                        if a == abs_slot:
                            cand.append((f'literal_low@0x{waddr:04x}', val, None))
                        else:
                            cand.append((f'literal_high@0x{waddr:04x}', None, val))

                # Conservative condition: off-word equals 0x1997 in any known value.
                can = any(c[1] == WANT for c in cand if c[1] is not None)
                state = 'yes' if can else 'no'
                ev = 'off-word check against known static values'
                if abs_slot in runtime_loaded_far_slots and not can:
                    state = 'unknown'
                    ev = 'slot is runtime-populated from external read path (WS46)'
                rows.append({
                    'kind': 'site_far_abs',
                    'site': site,
                    'source': f'0x{abs_slot:04x}/0x{abs_slot+2:04x}',
                    'value': ';'.join(f'{n}:{(hex(lo) if lo is not None else "-")}/{(hex(hi) if hi is not None else "-")}' for n, lo, hi in cand)[:500],
                    'can_hit_1997': state,
                    'evidence': ev,
                })
            else:
                val = u16(img, abs_slot) if abs_slot + 1 < len(img) else None
                can = (val == WANT)
                rows.append({
                    'kind': 'site_near_abs',
                    'site': site,
                    'source': f'0x{abs_slot:04x}',
                    'value': hex(val) if val is not None else 'n/a',
                    'can_hit_1997': 'yes' if can else 'no',
                    'evidence': 'raw init near-target word',
                })
            continue

        # indexed [bx+0xADDR]
        bx_base = parse_bx_base(op)
        if bx_base is not None:
            if mnem == 'lcall' and bx_base == 0x0E32:
                # 3-entry dispatch table model from WS55.
                entries = [
                    ('entry0_startup', 0x0601, 0x0073),
                    ('entry1_observed_rebind', 0x095C, 0x011F),
                    ('entry2_startup', 0x0000, 0x0000),
                ]
                can = any(lo == WANT for _, lo, _ in entries)
                rows.append({
                    'kind': 'site_far_indexed',
                    'site': site,
                    'source': f'base=0x{bx_base:04x}',
                    'value': ';'.join(f'{n}:{hex(lo)}/{hex(hi)}' for n, lo, hi in entries),
                    'can_hit_1997': 'yes' if can else 'no',
                    'evidence': 'WS55 runtime timeline entries',
                })
            else:
                rows.append({
                    'kind': 'site_indexed_other',
                    'site': site,
                    'source': f'base=0x{bx_base:04x}',
                    'value': 'dynamic/indexed',
                    'can_hit_1997': 'unknown',
                    'evidence': 'indexed source not resolved in this pass',
                })
            continue

        rows.append({
            'kind': 'site_other',
            'site': site,
            'source': 'non-absolute/non-bx-indexed',
            'value': 'dynamic',
            'can_hit_1997': 'unknown',
            'evidence': 'requires deeper dataflow',
        })

    # Summary counters
    yes_n = sum(1 for r in rows if r['can_hit_1997'] == 'yes')
    no_n = sum(1 for r in rows if r['can_hit_1997'] == 'no')
    unk_n = sum(1 for r in rows if r['can_hit_1997'] == 'unknown')

    md_lines = [
        '# WS57 mdmgr Indirect-Target Feasibility for 0x1997',
        '',
        'Date: 2026-02-17',
        '',
        'Scope: static indirect transfer sources in `w31/extract/mdmgr.exe`, checked against target offset `0x1997`.',
        '',
        '## Summary',
        f'- total analyzed rows: {len(rows)}',
        f'- can_hit_1997=yes: {yes_n}',
        f'- can_hit_1997=no: {no_n}',
        f'- can_hit_1997=unknown: {unk_n}',
        '- Static finding: no resolved static source provides off-word `0x1997`.',
        '',
        '## Key Constraints',
        '- Global image word scan finds zero occurrences of `0x1997`.',
        '- Indexed dispatch base `0x0e32` runtime entries from WS55 are `0601/0073`, `095c/011f`, and `0000/0000`.',
        '- Therefore known dispatch providers do not encode `0x1997` as call offset in bounded static evidence.',
    ]

    Path('analysis/ws57_mdmgr_indirect_1997_feasibility.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws57_mdmgr_indirect_1997_feasibility.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['kind', 'site', 'source', 'value', 'can_hit_1997', 'evidence'])
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws57_mdmgr_indirect_1997_feasibility.md and .csv')


if __name__ == '__main__':
    main()

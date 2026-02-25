#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

CL_START = 0x3994
CL_END = 0x3F4A
WALKER = 0x4209
TARGET_SLOT_START = 0x1978
TARGET_SLOT_END = 0x197C


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def main() -> None:
    p = Path('w31/extract/mdfsck.exe')
    b = p.read_bytes()
    hdr = u16(b, 0x08) * 16
    img = b[hdr:]

    cs = u16(b, 0x16)
    cs_base = cs << 4
    ds_seg = u16(img, cs_base + 0x12E)
    ds_base = ds_seg << 4

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(img, 0))

    callsites = []
    for i, x in enumerate(ins):
        if x.mnemonic != 'call' or x.op_str.strip() != '0x4209':
            continue
        # backtrack for SI/DI constant setup in a tiny window
        si = ''
        di = ''
        for y in reversed(ins[max(0, i - 6):i]):
            if not si and y.mnemonic == 'mov' and y.op_str.startswith('si, '):
                si = y.op_str.split(',')[1].strip()
            if not di and y.mnemonic == 'mov' and y.op_str.startswith('di, '):
                di = y.op_str.split(',')[1].strip()
        callsites.append(
            {
                'site': f'0x{x.address:04x}',
                'si': si,
                'di': di,
                'range_non_empty': 'yes' if si and di and si != di else 'no',
            }
        )

    slot_lin = ds_base + TARGET_SLOT_START
    tgt_off = u16(img, slot_lin)
    tgt_seg = u16(img, slot_lin + 2)
    tgt_lin = (tgt_seg << 4) + tgt_off

    # quick target-profile: instructions from target until first retf
    target_ins = []
    for x in md.disasm(img[tgt_lin:tgt_lin + 0x40], tgt_lin):
        target_ins.append(f'0x{x.address:04x}:{x.mnemonic} {x.op_str}')
        if x.mnemonic == 'retf':
            break

    # does target block call helper cluster directly?
    helper_hits = []
    for x in md.disasm(img[tgt_lin:tgt_lin + 0x40], tgt_lin):
        if x.mnemonic in ('call', 'lcall'):
            op = x.op_str.replace(' ', '')
            if x.mnemonic == 'call' and op.startswith('0x'):
                near = int(op, 16)
                lin = cs_base + near
                if CL_START <= lin < CL_END:
                    helper_hits.append(f'0x{x.address:04x}->0x{lin:04x}')
            if x.mnemonic == 'lcall' and ',' in op:
                seg_s, off_s = op.split(',')
                seg = int(seg_s, 16)
                off = int(off_s, 16)
                lin = (seg << 4) + off
                if CL_START <= lin < CL_END:
                    helper_hits.append(f'0x{x.address:04x}->{seg:04x}:{off:04x}(0x{lin:04x})')

    md_lines = [
        '# WS40 mdfsck Callback Walker Semantics',
        '',
        'Date: 2026-02-17',
        '',
        '## Segment Bases',
        f'- `CS=0x{cs:04x}` => `CS_base=0x{cs_base:04x}`',
        f'- `DS=0x{ds_seg:04x}` => `DS_base=0x{ds_base:04x}`',
        '',
        '## Walker Routine',
        '- `0x4209`: iterates far-pointer list over `[SI,DI)` in reverse 4-byte steps and executes `lcall [di]` when entry is non-zero.',
        '',
        '## Callsite Summary',
        '| site | SI | DI | non-empty range |',
        '| --- | --- | --- | --- |',
    ]

    for r in sorted(callsites, key=lambda x: int(x['site'], 16)):
        md_lines.append(f"| {r['site']} | {r['si'] or '-'} | {r['di'] or '-'} | {r['range_non_empty']} |")

    md_lines.extend([
        '',
        '## Static Callback Slot (image-init)',
        f'- list range used in non-empty case: `SI=0x{TARGET_SLOT_START:04x}`, `DI=0x{TARGET_SLOT_END:04x}`',
        f'- `[DS:0x{TARGET_SLOT_START:04x}] = 0x{tgt_off:04x}`, `[DS:0x{TARGET_SLOT_START+2:04x}] = 0x{tgt_seg:04x}` -> `far {tgt_seg:04x}:{tgt_off:04x}` (linear `0x{tgt_lin:04x}`)',
        f"- helper-cluster hit (`0x{CL_START:04x}..0x{CL_END:04x}`): {'yes' if CL_START <= tgt_lin < CL_END else 'no'}",
        '',
        '## Target Routine Prefix (resolved callback target)',
    ])
    md_lines.extend([f'- `{line}`' for line in target_ins])
    md_lines.extend([
        '',
        '## Reachability Note',
        '- This resolves `lcall [di]` into a bounded callback-list mechanism with one initial static entry.',
        '- Runtime mutation of callback slots remains possible; final closure still benefits from runtime capture.',
    ])

    Path('analysis/ws40_mdfsck_callback_walker.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')

    with open('analysis/ws40_mdfsck_callback_walker.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['site', 'si', 'di', 'range_non_empty', 'slot_start', 'slot_end', 'resolved_far', 'resolved_linear', 'hits_cluster'],
        )
        w.writeheader()
        for r in sorted(callsites, key=lambda x: int(x['site'], 16)):
            row = {
                'site': r['site'],
                'si': r['si'],
                'di': r['di'],
                'range_non_empty': r['range_non_empty'],
                'slot_start': f'0x{TARGET_SLOT_START:04x}',
                'slot_end': f'0x{TARGET_SLOT_END:04x}',
                'resolved_far': f'{tgt_seg:04x}:{tgt_off:04x}',
                'resolved_linear': f'0x{tgt_lin:04x}',
                'hits_cluster': 'yes' if CL_START <= tgt_lin < CL_END else 'no',
            }
            w.writerow(row)

    print('wrote analysis/ws40_mdfsck_callback_walker.md and .csv')


if __name__ == '__main__':
    main()

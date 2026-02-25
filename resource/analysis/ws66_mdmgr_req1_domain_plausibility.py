#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

TARGET = Path('w31/extract/mdmgr.exe')
TABLE = 0x07DF
DOMAIN = [9, 10, 11, 12, 13]


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def main() -> None:
    raw = TARGET.read_bytes()
    hdr = u16(raw, 0x08) * 16
    img = raw[hdr:]

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    full_ins = list(md.disasm(img, 0))
    boundaries = {x.address for x in full_ins}

    rows = []
    for req1 in DOMAIN:
        tgt = u16(img, TABLE + req1 * 2)
        in_img = tgt < len(img)
        pre = 'offimage'
        first = ''
        if in_img and tgt not in boundaries:
            pre = 'mid_instruction_entry'
        if in_img:
            ins = list(md.disasm(img[tgt:tgt + 0x20], tgt))
            head = ins[:4]
            first = ' | '.join(f'{x.mnemonic} {x.op_str}' for x in head)

            text = ' ; '.join((x.mnemonic + ' ' + x.op_str).lower().replace(' ', '') for x in head)
            # Heuristic for jump-entry compatibility with 0x0d31 frame.
            if pre == 'mid_instruction_entry':
                pass
            elif '[bp-' in text:
                pre = 'needs_local_bp_frame'
            elif '[bp+6]' in text or '[bp+8]' in text or '[bp+0xa]' in text:
                pre = 'uses_caller_args_bp_frame'
            else:
                pre = 'other'

        plausible = 'no'
        if pre == 'uses_caller_args_bp_frame':
            plausible = 'yes'
        elif pre == 'offimage':
            plausible = 'no'
        elif pre in ('needs_local_bp_frame', 'mid_instruction_entry'):
            plausible = 'no'
        else:
            plausible = 'unknown'

        rows.append(
            {
                'req1': str(req1),
                'target_off': f'0x{tgt:04x}',
                'in_image': 'yes' if in_img else 'no',
                'entry_precondition': pre,
                'jump_entry_plausible': plausible,
                'head_insns': first,
            }
        )

    yes_n = sum(1 for r in rows if r['jump_entry_plausible'] == 'yes')
    md_lines = [
        '# WS66 mdmgr req[+1] Domain Plausibility (Second Dispatch)',
        '',
        'Date: 2026-02-17',
        '',
        'Scope: guard-bounded domain `req[+1]=9..13` for `0x0e58 -> cs:[bx+0x07df]`.',
        '',
        '## Findings',
        f'- plausible jump-entry targets in domain: {yes_n}/{len(rows)}',
        '- `0x1047` is the only in-image target with immediate `bp+arg` usage pattern compatible with direct jump from handler frame.',
        '- `0x00b4` is in-image but not an instruction-boundary target (mid-instruction entry), making it non-plausible as direct dispatch destination.',
        '- Off-image targets remain non-plausible without external materialization not evidenced in current static pass.',
    ]

    Path('analysis/ws66_mdmgr_req1_domain_plausibility.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws66_mdmgr_req1_domain_plausibility.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['req1', 'target_off', 'in_image', 'entry_precondition', 'jump_entry_plausible', 'head_insns'],
        )
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws66_mdmgr_req1_domain_plausibility.md and .csv')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import csv


def main() -> None:
    rows = [
        {
            'dimension': 'dispatch_domain',
            'value': 'req[+1] in 9..13 (guarded)',
            'confidence': 'high',
            'evidence': 'WS63',
        },
        {
            'dimension': 'practical_subset',
            'value': 'req[+1]=9 (0x1047) only plausible in-image target',
            'confidence': 'high',
            'evidence': 'WS66',
        },
        {
            'dimension': 'entry_semantics',
            'value': '0x1047 tagged formatter path (0x45/0x48 by req[0x17])',
            'confidence': 'high',
            'evidence': 'WS67',
        },
        {
            'dimension': 'status_ownership',
            'value': 'handler sets req+3 status; 0x1047 does not overwrite status',
            'confidence': 'high',
            'evidence': 'WS68',
        },
        {
            'dimension': 'input_provenance',
            'value': 'req[0x10..0x17] read-mostly pre-assembled contract lanes',
            'confidence': 'medium-high',
            'evidence': 'WS69',
        },
        {
            'dimension': 'remaining_unknown',
            'value': 'exact external producer/semantic names of req fields and subtype label',
            'confidence': 'open',
            'evidence': 'WS64-WS69',
        },
    ]

    md_lines = [
        '# WS70 mdmgr Case-9 Provisional Subtype Profile',
        '',
        'Date: 2026-02-17',
        '',
        '## Profile Summary',
        '- Provisional subtype anchor: second-dispatch practical subset converges to `req[+1]=9`.',
        '- Control-flow, payload-shape, status ownership, and input-lane provenance are now mutually consistent in static evidence.',
        '- Recommended spec stance: treat case-9 as a stable provisional subtype profile while keeping semantic names/opcode label as `[UNKNOWN]`.',
        '',
        '## Consolidated Dimensions',
    ]
    for r in rows:
        md_lines.append(f"- `{r['dimension']}`: {r['value']} (`{r['confidence']}`, {r['evidence']})")

    md_lines.extend([
        '',
        '## Unknown Priority Reorder (Case-9 scope)',
        '1. External producer path that assembles `req[0x10..0x17]` contract bytes.',
        '2. Semantic naming/labeling of `req[+1]=9` subtype in MDCTL-level taxonomy.',
        '3. Runtime confirmation of non-selected domain values (`10..13`) under real protocol traffic.',
    ])

    Path('analysis/ws70_mdmgr_case9_subtype_profile.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws70_mdmgr_case9_subtype_profile.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['dimension', 'value', 'confidence', 'evidence'])
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws70_mdmgr_case9_subtype_profile.md and .csv')


if __name__ == '__main__':
    main()

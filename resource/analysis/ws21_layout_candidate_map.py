#!/usr/bin/env python3
from __future__ import annotations

import csv
import re
from pathlib import Path

SRC = Path('analysis/ws19_mdfsck_vd_emit_map.csv')
OUT_MD = Path('analysis/ws21_layout_candidate_map.md')
OUT_CSV = Path('analysis/ws21_layout_candidate_map.csv')
OUT_WS23 = Path('analysis/ws23_layout_confirmed_table.csv')


def parse_label(fmt_text: str) -> str:
    s = fmt_text.replace('\n', ' ').strip()
    m = re.search(r'([A-Za-z][A-Za-z0-9]+)\s*:\s*%', s)
    return m.group(1) if m else s


def parse_spec(fmt_text: str) -> str:
    m = re.search(r'(%(?:0?\d+)?l?[duxs])', fmt_text)
    return m.group(1) if m else ''


def width_from_spec(spec: str) -> tuple[str, int]:
    if spec == '%ld':
        return 'u32', 2
    if spec in ('%d', '%u', '%04x'):
        return 'u16', 1
    if spec == '%s':
        return 'str', 1
    return 'unknown', 0


def main() -> None:
    rows = list(csv.DictReader(SRC.read_text(encoding='utf-8').splitlines()))

    out = []
    for r in rows:
        label = parse_label(r['fmt_text'])
        spec = parse_spec(r['fmt_text'])
        dtype, nwords = width_from_spec(spec)
        globals_raw = [g.strip() for g in (r.get('pushed_globals_before_call') or '').split(',') if g.strip()]
        selected = globals_raw[-nwords:] if nwords and globals_raw else globals_raw
        out.append(
            {
                'field_label': label,
                'printf_spec': spec,
                'value_class': dtype,
                'value_words': str(nwords if nwords else ''),
                'candidate_globals': ','.join(selected),
                'all_globals_window': ','.join(globals_raw),
                'call_mem': r['call_mem'],
                'confidence': 'inferred',
                'notes': 'checker emit-lane mapping only; on-media offset unresolved',
            }
        )

    md = [
        '# WS21 Layout Candidate Map',
        '',
        'Date: 2026-02-17',
        '',
        'Source: `analysis/ws19_mdfsck_vd_emit_map.csv`.',
        '',
        '| field_label | printf_spec | value_class | value_words | candidate_globals | call_mem | confidence |',
        '| --- | --- | --- | --- | --- | --- | --- |',
    ]
    for r in out:
        md.append(
            f"| {r['field_label']} | {r['printf_spec']} | {r['value_class']} | {r['value_words']} | "
            f"{r['candidate_globals']} | {r['call_mem']} | {r['confidence']} |"
        )

    md.extend([
        '',
        '## Notes',
        '- `candidate_globals` uses trailing argument words by format-width heuristic.',
        '- This map identifies checker variable lanes, not byte-accurate media offsets.',
    ])

    OUT_MD.write_text('\n'.join(md) + '\n', encoding='utf-8')
    with OUT_CSV.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                'field_label', 'printf_spec', 'value_class', 'value_words', 'candidate_globals',
                'all_globals_window', 'call_mem', 'confidence', 'notes'
            ],
        )
        w.writeheader()
        w.writerows(out)

    # Update WS23 as a curated carry-forward table (still no on-media offsets yet).
    with OUT_WS23.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['record', 'field', 'offset', 'size', 'endian', 'confidence', 'notes'])
        w.writeheader()
        for r in out:
            size = '4' if r['value_class'] == 'u32' else ('2' if r['value_class'] == 'u16' else ('var' if r['value_class'] == 'str' else ''))
            w.writerow(
                {
                    'record': 'VD',
                    'field': r['field_label'],
                    'offset': '',
                    'size': size,
                    'endian': 'little' if size in ('2', '4') else '',
                    'confidence': 'inferred',
                    'notes': (
                        f"checker-lane {r['candidate_globals']} via {r['printf_spec']}; "
                        "post-load normalization indicates host little-endian value; "
                        "source byte order likely big-endian; media offset unknown"
                    ),
                }
            )

    print('wrote analysis/ws21_layout_candidate_map.md/.csv and refreshed ws23_layout_confirmed_table.csv')


if __name__ == '__main__':
    main()

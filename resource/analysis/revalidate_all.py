#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CheckResult:
    name: str
    status: str  # PASS/WARN/FAIL
    detail: str


def sha1(path: Path) -> str:
    h = hashlib.sha1()
    with path.open('rb') as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def parse_fingerprint_lines(text: str):
    # - `path`: size `123`, SHA-1 `hex`
    pat = re.compile(r"-\s+`([^`]+)`:\s+size\s+`(\d+)`,\s+SHA-1\s+`([0-9a-f]{40})`", re.IGNORECASE)
    out = []
    for m in pat.finditer(text):
        out.append((m.group(1), int(m.group(2)), m.group(3).lower()))
    return out


def parse_backtick_paths(text: str):
    return sorted(set(re.findall(r"`([^`]+)`", text)))


def looks_like_file_ref(token: str) -> bool:
    if token.startswith('0x'):
        return False
    if token.startswith('/') and not token.startswith(('./', '../')):
        # likely CLI option or syntax fragment
        return False
    if any(ch in token for ch in ['|', '<', '>', '(', ')']):
        return False
    if token.endswith((':',)):
        return False
    # Accept explicit workspace roots or file extensions/wildcards.
    if token.startswith(('analysis/', 'document/', 'w31/', 'w95/', 'resource/')):
        return True
    if '*' in token:
        return '/' in token
    if '/' in token and '.' in token:
        return True
    if token.endswith(('.md', '.csv', '.py', '.exe', '.vxd', '.inf', '.dll', '.sys', '.txt', '.pdf', '.hlp', '.wri')):
        return True
    return False


def ref_exists(token: str) -> bool:
    # Support wildcard refs such as analysis/ws2_*.*
    if '*' in token:
        return len(list(Path('.').glob(token))) > 0
    p = Path(token)
    if p.exists():
        return True
    # Resolve bare filenames against known roots.
    if '/' not in token:
        candidates = [
            Path('w31/extract') / token,
            Path('w95/extract/us') / token,
            Path('w95/extract/jp') / token,
            Path('w95/merged') / token,
            Path('analysis') / token,
            Path('document') / token,
        ]
        return any(c.exists() for c in candidates)
    return False


def main() -> int:
    results: list[CheckResult] = []

    spec_rfc = Path('document/MDFS_SPEC_RFC.md')
    spec = Path('document/MDFS_SPEC.md')
    spec_final = Path('document/MDFS_SPEC_FINAL.md')
    if not spec_rfc.exists() or not spec.exists() or not spec_final.exists():
        results.append(CheckResult('core_docs_exist', 'FAIL', 'One or more core spec docs missing'))
    else:
        results.append(CheckResult('core_docs_exist', 'PASS', 'Core spec docs present'))

    # 1) Fingerprint verification against RFC
    if spec_rfc.exists():
        fps = parse_fingerprint_lines(spec_rfc.read_text(encoding='utf-8', errors='replace'))
        if not fps:
            results.append(CheckResult('rfc_fingerprints', 'FAIL', 'No fingerprint lines parsed from RFC'))
        else:
            bad = []
            for p, sz, h in fps:
                fp = Path(p)
                if not fp.exists():
                    bad.append(f'missing:{p}')
                    continue
                if fp.stat().st_size != sz:
                    bad.append(f'size:{p} expected={sz} actual={fp.stat().st_size}')
                    continue
                hh = sha1(fp)
                if hh != h:
                    bad.append(f'sha1:{p} expected={h} actual={hh}')
            if bad:
                results.append(CheckResult('rfc_fingerprints', 'FAIL', '; '.join(bad)))
            else:
                results.append(CheckResult('rfc_fingerprints', 'PASS', f'{len(fps)} entries verified'))

    # 1b) Full manifest verification
    manifest = Path('document/MDFS_BINARY_MANIFEST.csv')
    if manifest.exists():
        rows = list(csv.DictReader(manifest.open()))
        bad = []
        for r in rows:
            p = Path(r['path'])
            if not p.exists():
                bad.append(f"missing:{r['path']}")
                continue
            sz = int(r['size'])
            h = r['sha1'].lower()
            if p.stat().st_size != sz:
                bad.append(f"size:{r['path']} expected={sz} actual={p.stat().st_size}")
                continue
            hh = sha1(p)
            if hh != h:
                bad.append(f"sha1:{r['path']} expected={h} actual={hh}")
        if bad:
            results.append(CheckResult('full_manifest', 'FAIL', '; '.join(bad[:8])))
        else:
            results.append(CheckResult('full_manifest', 'PASS', f'{len(rows)} rows verified'))
    else:
        results.append(CheckResult('full_manifest', 'WARN', 'document/MDFS_BINARY_MANIFEST.csv missing'))

    # 2) Check referenced path existence in major docs (best-effort)
    for doc in [spec_rfc, spec, spec_final, Path('document/MDFS_RE_PLAN.md'), Path('document/MDFS_EVIDENCE_GAP_AUDIT.md')]:
        if not doc.exists():
            continue
        text = doc.read_text(encoding='utf-8', errors='replace')
        paths = [p for p in parse_backtick_paths(text) if looks_like_file_ref(p)]
        missing = []
        for p in paths:
            if p.startswith('[') or p.startswith('-'):
                continue
            if not ref_exists(p):
                missing.append(p)
        if missing:
            results.append(CheckResult(f'ref_paths:{doc.name}', 'WARN', f'missing refs: {", ".join(sorted(set(missing))[:10])}'))
        else:
            results.append(CheckResult(f'ref_paths:{doc.name}', 'PASS', f'{len(paths)} refs resolved'))

    # 3) WS2 DDB candidate consistency
    ddb_csv = Path('analysis/ws2_vxd_ddb_candidates.csv')
    if ddb_csv.exists():
        rows = list(csv.DictReader(ddb_csv.open()))
        bad = [r for r in rows if r.get('name_match') != '1']
        if bad:
            results.append(CheckResult('ws2_ddb_name_match', 'FAIL', f'{len(bad)} rows with name_match!=1'))
        else:
            results.append(CheckResult('ws2_ddb_name_match', 'PASS', f'{len(rows)} rows name_match=1'))
    else:
        results.append(CheckResult('ws2_ddb_name_match', 'FAIL', 'analysis/ws2_vxd_ddb_candidates.csv missing'))

    # 4) WS2 page-map pattern sanity
    pagemap_csv = Path('analysis/ws2_le_pagemap.csv')
    if pagemap_csv.exists():
        rows = list(csv.DictReader(pagemap_csv.open()))
        bad = []
        for r in rows:
            raw = int(r['raw'])
            phys = int(r['physical_page'])
            if raw >> 16 != phys:
                bad.append((r['file'], r['page_index_1based']))
        if bad:
            results.append(CheckResult('ws2_pagemap_pattern', 'FAIL', f'invalid rows: {len(bad)}'))
        else:
            results.append(CheckResult('ws2_pagemap_pattern', 'PASS', f'{len(rows)} rows match raw>>16 rule'))
    else:
        results.append(CheckResult('ws2_pagemap_pattern', 'FAIL', 'analysis/ws2_le_pagemap.csv missing'))

    # 5) WS2 fixup table row counts by known page counts
    fix_csv = Path('analysis/ws2_le_fixup_summary.csv')
    if fix_csv.exists():
        rows = list(csv.DictReader(fix_csv.open()))
        counts = {}
        for r in rows:
            counts[r['file']] = counts.get(r['file'], 0) + 1
        expected = {
            'w95/extract/us/mdmgr.vxd': 33,
            'w95/extract/us/mdhlp.vxd': 14,
            'w95/extract/us/mdfsd.vxd': 147,
        }
        bad = []
        for k, v in expected.items():
            if counts.get(k) != v:
                bad.append(f'{k}: expected {v}, got {counts.get(k,0)}')
        if bad:
            results.append(CheckResult('ws2_fixup_rows', 'FAIL', '; '.join(bad)))
        else:
            results.append(CheckResult('ws2_fixup_rows', 'PASS', 'row counts match num_pages'))
    else:
        results.append(CheckResult('ws2_fixup_rows', 'FAIL', 'analysis/ws2_le_fixup_summary.csv missing'))

    # 6) US/JP VxD hash equality
    pairs = [
        ('w95/extract/us/mdfsd.vxd', 'w95/extract/jp/mdfsd.vxd'),
        ('w95/extract/us/mdmgr.vxd', 'w95/extract/jp/mdmgr.vxd'),
        ('w95/extract/us/mdhlp.vxd', 'w95/extract/jp/mdhlp.vxd'),
    ]
    bad = []
    for a, b in pairs:
        pa, pb = Path(a), Path(b)
        if not pa.exists() or not pb.exists():
            bad.append(f'missing pair: {a} / {b}')
            continue
        if sha1(pa) != sha1(pb):
            bad.append(f'hash mismatch: {a} vs {b}')
    if bad:
        results.append(CheckResult('us_jp_vxd_equivalence', 'FAIL', '; '.join(bad)))
    else:
        results.append(CheckResult('us_jp_vxd_equivalence', 'PASS', 'all three VxD pairs identical'))

    # 7) w31 extract count
    w31_files = [p for p in Path('w31/extract').iterdir() if p.is_file()] if Path('w31/extract').exists() else []
    if len(w31_files) == 13:
        results.append(CheckResult('w31_extract_count', 'PASS', '13 files present'))
    else:
        results.append(CheckResult('w31_extract_count', 'FAIL', f'expected 13 files, got {len(w31_files)}'))

    # 8) w31 installer/extract verification script
    verify_py = Path('verify_w31_install.py')
    if verify_py.exists():
        cp = subprocess.run(
            ['python3', str(verify_py), '--installer-dir', 'w31', '--installed-dir', 'w31/extract'],
            capture_output=True,
            text=True,
        )
        out = (cp.stdout or '') + (cp.stderr or '')
        if cp.returncode == 0 and 'RESULT: PASS' in out:
            results.append(CheckResult('w31_verify_script', 'PASS', 'verify_w31_install.py returned PASS'))
        else:
            results.append(CheckResult('w31_verify_script', 'FAIL', f'verify script failed rc={cp.returncode}'))
    else:
        results.append(CheckResult('w31_verify_script', 'WARN', 'verify_w31_install.py missing'))

    # render report
    report = []
    report.append('# MDFS Revalidation Report')
    report.append('')
    report.append('Date: 2026-02-16')
    report.append('Scope: docs + analysis artifacts + extracted drivers/tools')
    report.append('')
    for r in results:
        report.append(f'- [{r.status}] {r.name}: {r.detail}')

    fail_n = sum(1 for r in results if r.status == 'FAIL')
    warn_n = sum(1 for r in results if r.status == 'WARN')
    pass_n = sum(1 for r in results if r.status == 'PASS')
    report.append('')
    report.append(f'Summary: PASS={pass_n}, WARN={warn_n}, FAIL={fail_n}')

    if fail_n == 0 and warn_n == 0:
        report.append('Overall: PASS (no inconsistencies detected in automated checks)')
    elif fail_n == 0:
        report.append('Overall: PASS-WITH-WARNINGS (manual interpretation may be needed)')
    else:
        report.append('Overall: FAIL (see failed checks)')

    Path('document/MDFS_REVALIDATION_REPORT.md').write_text('\n'.join(report) + '\n', encoding='utf-8')

    print('\n'.join(report))
    return 0 if fail_n == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())

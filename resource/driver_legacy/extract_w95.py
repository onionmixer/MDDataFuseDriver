#!/usr/bin/env python3
"""
Reconstruct installed files from w95/merged into w95/extract.

Sources:
- SETUP.PKG: payload file list and logical installed names
- US/SETUP.INS and JP/SETUP.INS: locale-specific source->destination mapping
"""

from __future__ import annotations

import argparse
import re
import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PkgEntry:
    name: str
    disk: int
    size: int


def parse_setup_pkg(pkg_path: Path) -> list[PkgEntry]:
    data = pkg_path.read_bytes()
    entries: list[PkgEntry] = []
    seen: set[str] = set()
    # Scan whole blob because table includes padding/section breaks.
    for off in range(len(data) - 10):
        n = int.from_bytes(data[off : off + 2], "little")
        if not (4 <= n <= 20):
            continue
        end = off + 2 + n + 2 + 4
        if end > len(data):
            continue
        raw_name = data[off + 2 : off + 2 + n]
        if not all(32 <= b < 127 for b in raw_name):
            continue
        name = raw_name.decode("ascii")
        if "." not in name:
            continue
        disk = int.from_bytes(data[off + 2 + n : off + 2 + n + 2], "little")
        size = int.from_bytes(data[off + 2 + n + 2 : off + 2 + n + 6], "little")
        if not (0 <= disk <= 9 and 1 <= size < 10_000_000):
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        entries.append(PkgEntry(name=name, disk=disk, size=size))
    return entries


def parse_setup_ins_mapping(ins_path: Path) -> dict[str, str]:
    """
    Extract source->destination filename mapping from InstallShield INS binary.
    In this package the stream includes tokens like '<src>a' then '<dest>!'.
    """
    text = ins_path.read_bytes().decode("latin1", errors="ignore")
    tokens = re.findall(r"([A-Za-z0-9_]{2,12}\.[A-Za-z0-9_]{2,4})([a!])", text)
    mapping: dict[str, str] = {}
    for i in range(len(tokens) - 1):
        src, t1 = tokens[i]
        dst, t2 = tokens[i + 1]
        if t1 == "a" and t2 == "!":
            mapping[src.lower()] = dst.lower()
    return mapping


def find_ci_file(directory: Path, filename: str) -> Path | None:
    target = filename.lower()
    for p in directory.iterdir():
        if p.is_file() and p.name.lower() == target:
            return p
    return None


def extract_locale(
    merged_dir: Path, out_dir: Path, pkg_entries: list[PkgEntry], ins_map: dict[str, str]
) -> tuple[int, list[str]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    copied = 0
    warnings: list[str] = []
    pkg_names = {e.name.lower() for e in pkg_entries}
    # Use INS mapping as authority for locale-specific installed output.
    for src_name, dst_name in sorted(ins_map.items()):
        if src_name not in pkg_names and dst_name not in pkg_names:
            continue
        src_file = find_ci_file(merged_dir, src_name)
        if src_file is None:
            warnings.append(f"missing source for {dst_name} (expected {src_name})")
            continue
        dst_file = out_dir / dst_name
        shutil.copy2(src_file, dst_file)
        copied += 1
    return copied, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract w95 installed files")
    parser.add_argument("--merged-dir", default="w95/merged")
    parser.add_argument("--output-dir", default="w95/extract")
    args = parser.parse_args()

    merged_dir = Path(args.merged_dir)
    output_dir = Path(args.output_dir)
    if not merged_dir.is_dir():
        raise SystemExit(f"missing merged dir: {merged_dir}")

    pkg_entries = parse_setup_pkg(merged_dir / "SETUP.PKG")
    if not pkg_entries:
        raise SystemExit("failed to parse SETUP.PKG")

    us_map = parse_setup_ins_mapping(merged_dir / "US" / "SETUP.INS")
    jp_map = parse_setup_ins_mapping(merged_dir / "JP" / "SETUP.INS")

    # Clean output root then extract both locale views
    if output_dir.exists():
        shutil.rmtree(output_dir)
    (output_dir / "us").mkdir(parents=True, exist_ok=True)
    (output_dir / "jp").mkdir(parents=True, exist_ok=True)

    us_count, us_warn = extract_locale(merged_dir, output_dir / "us", pkg_entries, us_map)
    jp_count, jp_warn = extract_locale(merged_dir, output_dir / "jp", pkg_entries, jp_map)

    print(f"parsed pkg entries: {len(pkg_entries)}")
    print(f"US extracted files: {us_count}")
    print(f"JP extracted files: {jp_count}")
    for w in us_warn:
        print(f"[US warn] {w}")
    for w in jp_warn:
        print(f"[JP warn] {w}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

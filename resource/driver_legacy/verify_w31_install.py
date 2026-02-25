#!/usr/bin/env python3
"""
Validate MDH10 Win3.1 extraction by comparing:
1) expected files from INSTALL.DAT
2) metadata from *.RED archives
3) actual files in installed output directory
"""

from __future__ import annotations

import argparse
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RedEntry:
    name: str
    uncomp_size: int
    comp_size: int


def parse_red_archive(path: Path) -> list[RedEntry]:
    data = path.read_bytes()
    entries: list[RedEntry] = []
    off = 0
    while off < len(data):
        if data[off : off + 2] != b"RR":
            raise ValueError(f"{path}: invalid RED signature at offset {off}")
        comp = int.from_bytes(data[off + 8 : off + 12], "little")
        unc = int.from_bytes(data[off + 12 : off + 16], "little")
        raw_name = data[off + 26 : off + 38].split(b"\x00", 1)[0]
        name = raw_name.decode("ascii", "replace")
        entries.append(RedEntry(name=name, uncomp_size=unc, comp_size=comp))
        off = off + 39 + comp + 2
    return entries


def parse_install_dat(path: Path) -> list[tuple[str, str | None]]:
    # Returns tuples of: (filename, source_lib_or_none)
    expected: list[tuple[str, str | None]] = []
    in_lib: str | None = None
    for raw_line in path.read_text(encoding="latin1", errors="replace").splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"@BeginLib\s+([^\s]+)", line, flags=re.IGNORECASE)
        if m:
            in_lib = m.group(1).strip()
            continue
        if re.match(r"@EndLib\b", line, flags=re.IGNORECASE):
            in_lib = None
            continue
        # @FILE mdmgr.exe ...
        m = re.match(r"@FILE\s+([^\s]+)", line)
        if m and in_lib:
            expected.append((m.group(1).strip(), in_lib))
            continue
        # @File read.me
        m = re.match(r"@File\s+([^\s]+)", line)
        if m:
            expected.append((m.group(1).strip(), None))
            continue
    # case-insensitive unique preserve order
    seen: set[tuple[str, str | None]] = set()
    out: list[tuple[str, str | None]] = []
    for name, src in expected:
        key = (name.lower(), src.lower() if src else None)
        if key in seen:
            continue
        seen.add(key)
        out.append((name, src))
    return out


def sha1_file(path: Path) -> str:
    h = hashlib.sha1()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def find_case_insensitive_file(directory: Path, filename: str) -> Path | None:
    target = filename.lower()
    for p in directory.iterdir():
        if p.is_file() and p.name.lower() == target:
            return p
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify MDH10 extraction result")
    parser.add_argument("--installer-dir", default="w31", help="directory with INSTALL.DAT and *.RED")
    parser.add_argument("--installed-dir", default="md31out", help="directory with extracted installed files")
    parser.add_argument("--install-dat", default=None, help="explicit INSTALL.DAT path (default: <installer-dir>/INSTALL.DAT)")
    args = parser.parse_args()

    installer_dir = Path(args.installer_dir)
    installed_dir = Path(args.installed_dir)
    install_dat = Path(args.install_dat) if args.install_dat else installer_dir / "INSTALL.DAT"

    if not installer_dir.is_dir():
        raise SystemExit(f"installer-dir not found: {installer_dir}")
    if not installed_dir.is_dir():
        raise SystemExit(f"installed-dir not found: {installed_dir}")
    if not install_dat.is_file():
        raise SystemExit(f"INSTALL.DAT not found: {install_dat}")

    red_archives: dict[str, dict[str, RedEntry]] = {}
    for red_path in sorted(installer_dir.glob("*.RED")):
        entries = parse_red_archive(red_path)
        red_archives[red_path.name.lower()] = {e.name.lower(): e for e in entries}

    expected = parse_install_dat(install_dat)
    installed_files = {
        p.name.lower(): p for p in installed_dir.iterdir() if p.is_file()
    }

    errors: list[str] = []
    verified: list[str] = []
    expected_installed_names: set[str] = set()

    for file_name, src_lib in expected:
        file_key = file_name.lower()
        actual = installed_files.get(file_key)
        expected_installed_names.add(file_key)
        if actual is None:
            errors.append(f"missing installed file: {file_name}")
            continue

        if src_lib is None:
            src = find_case_insensitive_file(installer_dir, file_name)
            if src is None:
                errors.append(f"source file not found in installer: {file_name}")
                continue
            if src.stat().st_size != actual.stat().st_size:
                errors.append(
                    f"size mismatch (direct file) {file_name}: installer={src.stat().st_size}, installed={actual.stat().st_size}"
                )
                continue
            if sha1_file(src) != sha1_file(actual):
                errors.append(f"hash mismatch (direct file) {file_name}")
                continue
            verified.append(f"{file_name}: direct copy OK")
            continue

        lib_key = src_lib.lower()
        lib_entries = red_archives.get(lib_key)
        if lib_entries is None:
            errors.append(f"library missing in installer: {src_lib}")
            continue
        red_entry = lib_entries.get(file_key)
        if red_entry is None:
            errors.append(f"{file_name}: not found in {src_lib}")
            continue
        actual_size = actual.stat().st_size
        if actual_size != red_entry.uncomp_size:
            errors.append(
                f"size mismatch {file_name}: installed={actual_size}, expected_uncomp={red_entry.uncomp_size} from {src_lib}"
            )
            continue
        verified.append(
            f"{file_name}: size OK ({actual_size}) from {src_lib}"
        )

    extras = sorted(
        p.name for k, p in installed_files.items() if k not in expected_installed_names
    )
    if extras:
        errors.append(f"unexpected installed files: {', '.join(extras)}")

    print("=== MDH10 Extraction Verification ===")
    print(f"installer-dir : {installer_dir}")
    print(f"install-dat   : {install_dat}")
    print(f"installed-dir : {installed_dir}")
    print(f"expected files: {len(expected)}")
    print(f"installed files: {len(installed_files)}")
    print()
    for line in verified:
        print(f"[OK] {line}")
    print()
    if errors:
        print(f"RESULT: FAIL ({len(errors)} issue(s))")
        for err in errors:
            print(f"[ERR] {err}")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

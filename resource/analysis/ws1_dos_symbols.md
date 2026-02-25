# WS1 DOS Symbols and Control Surface

Date: 2026-02-16
Scope: `w31/extract/mdfsex.exe`, `w31/extract/mdfsck.exe`, `w31/extract/mdformat.exe`, `w31/extract/mdmgr.exe`, `w31/extract/mdcache.exe`

## Evidence Method
- Primary: `strings -a -t x` (string + file offset)
- Installer mapping: `w31/INSTALL.DAT`, `w31/*.RED`
- Validation: `python3 verify_w31_install.py --installer-dir w31 --installed-dir w31/extract` => `RESULT: PASS`

## mdfsex.exe (filesystem loader)
- Banner: `0x0000b54e` `MD DATA File System, version 1.11`
- CLI usage: `0x0000b6d2` `Usage:` and `0x0000b6da` `[/L:<drive>]`
- Config tokens: `0x0000b5ba` `MDMGR=` and `0x0000b5c2` `LUN=`
- Device/control tokens: `0x0000b720` `MDCTL`, `0x0000b726` `MD001`, `0x0000b73f` `MDFS000`
- Error set:
  - `0x0000b5ca` unsupported DOS
  - `0x0000b636` already installed
  - `0x0000b65a` drive letter unavailable
  - `0x0000b686` no MD DATA device

## mdmgr.exe (device manager)
- Banner: `0x00002a4e` `MD DATA Device Manager, version 1.2`
- Device scan flow: `0x00002afc` `search for MD DATA devices...`
- Cache state status:
  - `0x00002b4a` write cache not enabled
  - `0x00002b67` write cache enabled
- Control/service tokens: `0x000027a6` `IOMR000`, `0x00002a26` `MDMR000`, `0x00002b9b` `MDFSEX01`

## mdcache.exe (cache control tool)
- Banner: `0x0000cd04` `MDcache version 1.0`
- CLI syntax: `0x0000cf22` `mdcache [-?] [drive:] ON | OFF | IS | FLUSH`
- Device endpoint evidence:
  - `0x0000ca40` `Unable to access \MDCTL`
  - `0x0000d03e` `D:\MDCTL`
  - `0x0000d047` `Z:\MDCTL`
- Command/behavior tokens:
  - `0x0000cdf6` write cache enabled
  - `0x0000ce42` write cache disabled
  - `0x0000ce90` write cache flushed

## mdformat.exe (formatter)
- Banner: `0x00019248` `MDformat version 1.95`
- Syntax: `0x000195f0` `mdformat drive: [-q | -s] [-o -v:label -?]`
- Mode text:
  - `0x000193e0` quick format message
  - `0x0001940c` safe format (35 min) message
- Media/FS checks:
  - `0x0001934f` error installing file system
  - `0x0001956f` media must be formatted with `-s`
  - `0x0001959f` volume descriptor inhibits format

## mdfsck.exe (checker)
- Banner: `0x0000e578` `MDfsck version 1.4`
- Syntax: `0x0000e5de` `mdfsck drive: [-v?]`
- Volume descriptor field labels (used by checker output):
  - Starts at `0x0000e781` (`Identifier`) through `0x0000ea09` (`ExTime`)
- Logical section labels:
  - `0x0000ec34` `VOLUME SPACE BITMAP:`
  - `0x0000ed33` `MANAGEMENT TABLE:`
  - `0x0000f063` `DIRECTORIES:`

## Confirmed vs Inferred
- Confirmed:
  - CLI grammar and user-visible command set for all 5 DOS tools.
  - Presence of control path tokens (`MDCTL`, `MD001`, `MDFS000`, `IOMR000`, `MDMR000`).
  - `mdfsck` prints detailed VD/bitmap/management/directory validation fields.
- Inferred:
  - `mdcache` and `mdfsex` use driver/device-control requests via `\MDCTL` family endpoints.
  - `mdmgr` is a prerequisite control layer consumed by `mdfsex` and cache tooling.
- Not yet recovered in WS1:
  - Numeric opcode table for control requests.
  - Exact record struct member offsets inside on-media VD/VSB/MTB/ERB/DRB blocks.

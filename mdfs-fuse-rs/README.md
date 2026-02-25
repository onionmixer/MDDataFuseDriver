# mdfs-fuse-rs (Scaffold)

Minimal workspace scaffold mapped from `PLAN_fuse_MDFS_DEV.md`.

Current scope:
- `mdfs-layout`: case-9 (`req[+1]=9`) parser contract and tests
- `mdfs-image`: image read trait + in-memory adapter
- `mdfs-index`: normalized record model
- `mdfs-fuse`: unknown-path/error policy scaffold (`EIO` fail-closed, optional `ENOTSUP` mode) + log format
- `mdfsck-lite`: placeholder CLI

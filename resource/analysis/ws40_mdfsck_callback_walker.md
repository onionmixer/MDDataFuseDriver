# WS40 mdfsck Callback Walker Semantics

Date: 2026-02-17

## Segment Bases
- `CS=0x03f7` => `CS_base=0x3f70`
- `DS=0x0dcd` => `DS_base=0xdcd0`

## Walker Routine
- `0x4209`: iterates far-pointer list over `[SI,DI)` in reverse 4-byte steps and executes `lcall [di]` when entry is non-zero.

## Callsite Summary
| site | SI | DI | non-empty range |
| --- | --- | --- | --- |
| 0x4153 | 0x1978 | 0x1978 | no |
| 0x415c | 0x1978 | 0x1978 | no |
| 0x4165 | 0x197c | 0x197c | no |
| 0x4199 | 0x5b22 | 0x5b22 | no |
| 0x41a2 | 0x1978 | 0x197c | yes |
| 0x41b7 | 0x197c | 0x197c | no |
| 0x41c0 | 0x197c | 0x197c | no |

## Static Callback Slot (image-init)
- list range used in non-empty case: `SI=0x1978`, `DI=0x197c`
- `[DS:0x1978] = 0x0796`, `[DS:0x197a] = 0x03f7` -> `far 03f7:0796` (linear `0x4706`)
- helper-cluster hit (`0x3994..0x3f4a`): no

## Target Routine Prefix (resolved callback target)
- `0x4706:push bp`
- `0x4707:mov bp, sp`
- `0x4709:lcall 0x3f7, 0xabc`
- `0x470e:mov al, byte ptr [0x14d1]`
- `0x4711:or al, al`
- `0x4713:je 0x471a`
- `0x4715:lcall 0x3f7, 0x180e`
- `0x471a:pop bp`
- `0x471b:retf `

## Reachability Note
- This resolves `lcall [di]` into a bounded callback-list mechanism with one initial static entry.
- Runtime mutation of callback slots remains possible; final closure still benefits from runtime capture.

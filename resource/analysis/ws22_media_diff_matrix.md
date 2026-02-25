# WS22 Media Diff Matrix

Date: 2026-02-17
Status: pre-trace matrix (ready for live media diff run)

## Purpose
Define deterministic operation matrix for mapping checker-visible VD fields to on-media offsets via sector diff.

## Baseline Inputs
- Field/lane map: `analysis/ws21_layout_candidate_map.csv`
- Validation/print path: `analysis/ws19_mdfsck_vd_emit_map.csv`

## Operation Matrix
| op_id | operation | expected checker-visible change | expected affected field families | confidence |
| --- | --- | --- | --- | --- |
| O1 | quick format (`mdformat -q -o`) | full initialization | Identifier/Version/BlockSize/ClusterSize/Alloc counters/LocNum tuples | inferred |
| O2 | safety format (`mdformat -s -o`) | initialization + certification deltas | O1 fields + defect/recordable counters | inferred |
| O3 | cache ON/OFF/FLUSH (`mdcache`) | likely metadata/control only (possibly none on media) | uncertain | unknown |
| O4 | fsck read-only pass (`mdfsck`) | no intended media mutation | none (control) | inferred |
| O5 | directory/file add/remove (if tooling available) | counter and dir-tree metadata shifts | NumDir/NumFile/NumUsed/NumAvailable/DirLen/NumChild | inferred |

## Diff Capture Template
For each run pair `(before.img, after.img)`:
1. Compute changed sector list.
2. Cluster sectors by contiguous ranges.
3. For each cluster, map candidate fields using checker output deltas.
4. Record in `ws23` only when cluster->field relation is repeatable in >=2 runs.

## Output Requirements
- sector delta table: `run_id,sector_start,sector_count,byte_diff_count,candidate_fields,confidence`
- mutation summary: `run_id,checker_field,delta_value,matched_sector_cluster`

## Promotion Rule
Promote `offset` from unknown only when:
- same field change maps to same sector/byte region in repeated runs, and
- no competing field explains the same region change better.

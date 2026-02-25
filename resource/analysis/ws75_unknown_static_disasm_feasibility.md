# WS75 UNKNOWN Closure Feasibility by Static Disassembly

Date: 2026-02-17

## Verdict
- 정적 역어셈블리만으로 `모든` UNKNOWN을 닫는 것은 불가능에 가깝다.
- 다만 일부 항목은 정적으로 추가 축소(`partial`)가 가능하며,
  최종 확정에는 런타임/미디어 증거가 필요하다.

## Itemized Feasibility
- `VD/VSB/MTB/ERB/DRB 온디스크 정확 오프셋` -> static `unlikely`; priority `P0`; fuse impact `real_mount_blocker`
  - why: 현재 증거는 checker 내부 글로벌 lane/출력 포맷 매핑까지이며, 미디어 바이트 위치를 직접 고정하는 상수/테이블 증거가 부족
  - cross: win31: ws21/ws23 lane map, win95: driver role/dispatch only
  - close: 실미디어 전/후 이미지 차분 + 런타임 버퍼 캡처
  - anchors: analysis/ws21_layout_candidate_map.md; analysis/ws23_layout_confirmed_table.csv; document/MDFS_SPEC_FINAL.md
- `MDCTL opcode<->payload 완전 스키마` -> static `partial`; priority `P1`; fuse impact `optional_for_ro`
  - why: opcode 후보/descriptor는 정적으로 강하게 좁혀졌지만 payload field 의미/방향성은 호출 시점 버퍼 캡처가 필요
  - cross: win31 mdcache/mdformat dual tables + mdfsck frame builders, win95 mdmgr dispatch narrowing
  - close: DOS/Win95 런타임 ioctl 프레임 캡처(WS25 plan)
  - anchors: analysis/ws9_mdctl_dual_table.md; analysis/ws33_mdctl_opcode_crosswalk.md; analysis/ws25_mdctl_runtime_capture.md
- `Win95 MDMGR<->MDFSD mount handshake 정확 시퀀스` -> static `partial`; priority `P1`; fuse impact `non_blocker_if_fail_closed`
  - why: 정적 분석으로 벡터/분기/table은 축소됐으나 외부 로딩 far pointer(0x0c42) 실제 값과 호출 순서는 실행 추적 필요
  - cross: win95 mdmgr vector population + startup table timeline, win31 callback ABI parity
  - close: Win95 런타임 call trace (QEMU/bochs instrumentation)
  - anchors: analysis/ws59_mdmgr_c42_load_chain_audit.md; analysis/ws55_mdmgr_e32_state_timeline.md; analysis/ws44_cross_binary_callback_abi.md
- `LE type-3 flags(0x03) 비트 의미` -> static `unlikely`; priority `P2`; fuse impact `low`
  - why: 표본 3개에서 flags가 모두 동일(0x03)이라 정적 비교로는 비트 의미 분해가 불가능
  - cross: win95 us/jp 동일, ddb export 상관성은 확인
  - close: 변이 바이너리 로더 동작 실험(WS28 next proof)
  - anchors: analysis/ws27_le_type3_flags_survey.md; analysis/ws28_le_type3_flags_hypothesis.md
- `case-9 req[0x10..0x17] 외부 생산자 semantic naming` -> static `partial`; priority `P1`; fuse impact `covered_by_unknown_policy`
  - why: 소비 경로는 충분히 좁혀졌으나 producer path는 runtime-loaded lane와 연결되어 이름/의미 확정 어려움
  - cross: win95 ws64..ws70, win31 shared callback ABI
  - close: producer side runtime frame provenance capture
  - anchors: analysis/ws70_mdmgr_case9_subtype_profile.md; analysis/ws64_mdmgr_req1_provenance_partition.md; analysis/ws73_fuse_unknown_path_policy.md

## Practical Next Action
1. P0: 온디스크 오프셋 폐쇄용 미디어 차분/버퍼 캡처부터 수행
2. P1: MDCTL payload/handshake runtime trace 수집
3. P2: LE flags는 변이 실험으로만 의미 분해 가능

# WS83 ERB 구조 분석

Date: 2026-02-24
Source: VD 필드 (ERBLoc/ERBNum/NumDefective) + mdfsck 글로벌 xref (WS36) + VSB 비트맵 DEFECTIVE 상태 (WS80)
Method: VD 필드 확인, mdfsck 코드 참조 분석, VMA 레이아웃 대조

## 1. ERB 개요

**ERB (Error Record Block)** = 결함 AU 추적 테이블 (추정) `INFERRED`

위치: VMALoc + ERBLoc (테스트 미디어에서는 미할당)

역할: 결함(defective) AU의 위치/상태를 기록하는 관리 테이블 (추정).
VSB 비트맵의 DEFECTIVE 상태(10)와 연동하여 결함 AU 상세 정보를 관리할 것으로 추정.

## 2. 테스트 미디어 상태

```
VD 필드:
  ERBLoc     = 0 (VD +0x4C, BE16) → 미할당
  ERBNum     = 0 (VD +0x4E, BE16) → 0 섹터
  NumDefective = 0 (VD +0x28, BE32) → 결함 AU 없음
```

테스트 미디어(MD DATA 140MB disc)에는 결함 AU가 없으므로 ERB가 할당되지 않음.
**ERB 온디스크 데이터 없음 — 내부 구조 분석 불가.**

## 3. VMA 레이아웃에서의 ERB 위치

```
VMALoc = 1056 (LBA), VMALen = 12288 bytes (6 sectors)

+0 (VD):   LBA 1056  [1 sector]   CONFIRMED
+1 (VSB):  LBA 1057  [3 sectors]  CONFIRMED (WS80)
+4 (MTB):  LBA 1060  [1 sector]   CONFIRMED (WS81)
+0 (ERB):  — 미할당 (ERBLoc=0, ERBNum=0)
+5 (DRB):  LBA 1061  [1 sector]   CONFIRMED (WS82)
```

ERBLoc=0은 VMA 시작과 겹치지만, ERBNum=0이므로 실제로 할당된 섹터 없음.
결함 AU가 있는 디스크에서는 ERBLoc > 0이 될 것으로 예상.

## 4. mdfsck 코드 참조

### 4.1 ERBLoc (0x5b7c) — 4개 xref

| 주소 | 명령 | 컨텍스트 |
|------|------|---------|
| 0x04fd | `mov ah, [0x5b7c]` | VD 로딩 후 엔디안 정규화 (WS37) |
| 0x0501 | `mov [0x5b7c], ax` | 정규화된 값 저장 |
| 0x07d8 | `push [0x5b7c]` | VD emit 블록 — "ERBLoc: %d" 출력 |
| 0x0f28 | `mov ax, [0x5b7c]` | **검증 루프** — MTBLoc과 함께 로딩 |

### 4.2 ERBNum (0x5b7e) — 3개 xref

| 주소 | 명령 | 컨텍스트 |
|------|------|---------|
| 0x0507 | `mov ah, [0x5b7e]` | VD 로딩 후 엔디안 정규화 (WS37) |
| 0x050b | `mov [0x5b7e], ax` | 정규화된 값 저장 |
| 0x07e8 | `push [0x5b7e]` | VD emit 블록 — "ERBNum: %d" 출력 |

### 4.3 검증 루프 (0x0f28) 분석

```asm
0x0f1f: mov ax, [0x5b78]    ; ax = MTBLoc (VD 0x48)
0x0f22: mov [bp-0x10], ax   ; local = MTBLoc
0x0f25: mov [bp-0x0e], si   ; local = 0
0x0f28: mov ax, [0x5b7c]    ; ax = ERBLoc (VD 0x4C)
0x0f2b: mov [bp-0x28], ax   ; local = ERBLoc
0x0f2e: mov [0x9a], si      ; global = 0
0x0f32: mov [bp-0x18], si   ; local = 0
0x0f35: cmp [0x5b7a], si    ; MTBNum(VD 0x4A) == 0?
0x0f39: jne 0x0f3e          ; MTBNum != 0 → 계속
0x0f3b: jmp 0x131c          ; MTBNum == 0 → 건너뜀
```

- ERBLoc은 MTBLoc과 함께 검증 루프의 파라미터로 사용됨
- 검증 진입 조건: MTBNum > 0 (MTB 없으면 ERB 검증도 건너뜀)
- ERBLoc이 [bp-0x28]에 저장되어 이후 로직에서 참조 (경계 마커 또는 ERB 검증용)
- 실제 ERB 레코드 파싱 로직은 이 코드 스니펫만으로는 확정 불가

## 5. 구조적 추론

### 5.1 VMA 관리 블록 패턴

| 블록 | Loc 필드 | Num 필드 | 내부 구조 | 상태 |
|------|---------|---------|----------|------|
| VSB | VSBLoc(0x44) | VSBNum(0x46) | 2-bit/AU 비트맵 | CONFIRMED (WS80) |
| MTB | MTBLoc(0x48) | MTBNum(0x4A) | TLV 레코드 | CONFIRMED (WS81) |
| ERB | ERBLoc(0x4C) | ERBNum(0x4E) | **UNKNOWN** | — |
| DRB | DRBLoc(0x50) | DRBNum(0x52) | 가변 길이 레코드 | CONFIRMED (WS82) |

### 5.2 ERB 역할 추정 `INFERRED`

| 근거 | 내용 |
|------|------|
| VD NumDefective | 결함 AU 수 추적 (BE32, VD 0x28) |
| VSB DEFECTIVE 상태 | 비트맵에서 결함 AU = 상태 코드 10 |
| ERBLoc/ERBNum | VMA 내 Loc/Num 쌍 → VSB/MTB/DRB와 동일 패턴 |
| mdfsck 검증 코드 | MTBLoc과 함께 로딩 → 인접 관리 블록 |

추정 역할: 결함 AU의 물리/논리 위치를 기록하는 테이블.
VSB 비트맵은 결함 여부만 나타내고 (2-bit), ERB는 결함 상세 정보
(물리 결함 위치, 대체 AU 매핑 등)를 저장할 수 있음.

### 5.3 ERB ↔ NumDefective 관계 `INFERRED`

```
NumDefective == 0 → ERBLoc = 0, ERBNum = 0 (ERB 미할당)
NumDefective > 0 → ERBLoc > 0, ERBNum > 0 (ERB 할당)
```

이 관계는 단일 디스크에서만 관찰되었으므로 확정 불가.
결함이 있는 디스크에서 검증 필요.

## 6. 확정 사항 vs 미확정 사항

### CONFIRMED

| 항목 | 근거 |
|------|------|
| ERBLoc VD 필드: 0x4C, BE16 | WS78/WS79 |
| ERBNum VD 필드: 0x4E, BE16 | WS78/WS79 |
| NumDefective VD 필드: 0x28, BE32 | WS78/WS79 |
| 테스트 미디어: ERBLoc=0, ERBNum=0, NumDefective=0 | WS78 |
| VSB DEFECTIVE 상태 코드: 10 | WS80 |
| mdfsck에서 ERBLoc/ERBNum 읽기/출력 | WS36/WS19 |
| 위치 해석: absolute LBA = VMALoc + ERBLoc | WS79 |

### INFERRED

| 항목 | 근거 |
|------|------|
| ERB = 결함 AU 추적 테이블 | NumDefective + VSB DEFECTIVE 상태 + ERB 이름 |
| NumDefective == 0이면 ERB 미할당 | 단일 디스크 관찰 |

### UNKNOWN

| 항목 | 필요 조건 |
|------|----------|
| ERB 내부 레코드 구조 | 결함 AU가 있는 디스크 |
| ERB 레코드 포맷 (고정/가변, 필드 배치) | 실제 ERB 데이터 |
| ERB와 VSB DEFECTIVE 상태의 정확한 연동 방식 | 결함 디스크 교차 검증 |
| 대체 AU 매핑 존재 여부 | 결함 디스크 분석 |
| ERBLoc이 0이 아닌 경우의 VMA 레이아웃 | 결함 디스크 VD |

## 7. FUSE 구현 사양

```rust
// ERB 관련 VD 필드
struct ErbInfo {
    erb_loc: u16,        // VD +0x4C, VMA 기준 상대 섹터 오프셋
    erb_num: u16,        // VD +0x4E, ERB 섹터 수
    num_defective: u32,  // VD +0x28, 결함 AU 수
}

// ERB 존재 여부 확인
fn has_erb(info: &ErbInfo) -> bool {
    info.erb_num > 0 && info.erb_loc > 0
}

// FUSE 마운트 시 ERB 처리 정책
// - NumDefective == 0: ERB 무시 (정상 디스크)
// - NumDefective > 0: ERB 파싱 시도, 실패 시 읽기 전용 마운트 + 경고 로그
// - ERB 내부 구조 미확정이므로, 결함 AU는 VSB DEFECTIVE 상태로 감지하고
//   해당 AU 접근 시 EIO 반환
fn handle_defective_au(au: u32, vsb_state: u8) -> Result<(), i32> {
    if vsb_state == 0b10 {  // DEFECTIVE
        Err(-libc::EIO)
    } else {
        Ok(())
    }
}
```

## 8. 미해결 사항

- ERB 내부 레코드 구조 전체 (데이터 없음)
- ERBLoc과 VMA 내 다른 블록과의 위치 관계 (결함 디스크 필요)
- mdfsck 0x0f28 이후의 ERB 검증 로직 전체 흐름 (상세 역어셈블리 필요)
- 결함 AU 대체 매핑 메커니즘 존재 여부

## 9. 결론

ERB는 테스트 미디어에 데이터가 존재하지 않아 내부 구조 분석이 불가.
VD 필드(ERBLoc, ERBNum, NumDefective)와 mdfsck 코드 참조로부터
"결함 AU 추적 테이블"이라는 역할만 추론 가능.

FUSE 구현에서는 ERB 내부 파싱 없이 VSB DEFECTIVE 상태 코드만으로
결함 AU를 감지하고 EIO를 반환하는 방식으로 우회 가능.
ERB 내부 구조 확정은 결함 AU가 있는 디스크 획득 시까지 보류.

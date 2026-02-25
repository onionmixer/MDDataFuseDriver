# WS84 VMA 영역 종합 구조

Date: 2026-02-24
Source: WS78/79 (VD), WS80 (VSB), WS81 (MTB), WS82 (DRB), WS83 (ERB) 종합
Method: 전체 VMA 블록 배치 확인, AU 레이아웃 통합, 교차 검증 집계

## 1. 개요

MDFS Volume Management Area (VMA)는 파일시스템 메타데이터를 담는 연속 영역.
5개 관리 블록(VD, VSB, MTB, ERB, DRB)으로 구성되며, VD의 Loc/Num 필드로 위치가 지정됨.

## 2. 디스크 파라미터

| 파라미터 | 값 | 설명 |
|---------|-----|------|
| BlockSize | 2,048 bytes | 섹터 크기 |
| AllocSize | 4 sectors | 할당 단위 (AU) 크기 |
| 1 AU | 8,192 bytes | = AllocSize × BlockSize |
| NumAlloc | 17,616 AU | 전체 AU 수 |
| 총 용량 | 70,464 sectors = 137.6 MiB | = NumAlloc × AllocSize |
| VMALoc | LBA 1056 (AU 264) | VMA 시작 위치 |
| VMALen | 12,288 bytes = 6 sectors | VMA 전체 크기 |

## 3. VMA 블록 배치

### 3.1 블록 테이블

```
VMA+offset  LBA     섹터수  블록    역할                              상태
─────────  ─────   ──────  ────   ─────────────────────────────────  ──────────
VMA+0      1056    1       VD     Volume Descriptor                  CONFIRMED
VMA+1      1057    3       VSB    Volume Space Bitmap (AU 비트맵)    CONFIRMED
VMA+4      1060    1       MTB    Management Table (FREE AU 카운트)  CONFIRMED
(없음)     —       0       ERB    Error Record Block (결함 AU)       UNKNOWN
VMA+5      1061    1       DRB    Directory Record Block (디렉토리)  CONFIRMED
─────────  ─────   ──────  ────   ─────────────────────────────────  ──────────
합계               6              = VMALen / BlockSize               완전 사용
```

### 3.2 연속성

모든 블록이 갭 없이 연속 배치:

```
VMA+0   VMA+1   VMA+2   VMA+3   VMA+4   VMA+5
┌──────┬──────┬──────┬──────┬──────┬──────┐
│  VD  │VSB[0]│VSB[1]│VSB[2]│  MTB │  DRB │
│ 1056 │ 1057 │ 1058 │ 1059 │ 1060 │ 1061 │
└──────┴──────┴──────┴──────┴──────┴──────┘
AU 264          AU 264          AU 265
```

VMALen = 6 sectors = 할당된 블록 합계. 잔여 공간 = 0.

ERB는 미할당 (NumDefective=0). 결함 AU가 있는 디스크에서는 MTB와 DRB 사이 또는
DRB 이후에 배치될 것으로 추정 (VMA 확장 필요).

### 3.3 VMA 위치 참조 해석

```
absolute LBA = VMALoc + xLoc

VSBLoc = 1 → LBA 1057   (VMALoc + 1)
MTBLoc = 4 → LBA 1060   (VMALoc + 4)
ERBLoc = 0 → 미할당      (ERBNum = 0)
DRBLoc = 5 → LBA 1061   (VMALoc + 5)
```

VD 자체는 VMALoc (LBA 1056)에 위치하며 별도의 Loc 필드 없음.

## 4. 블록별 구조 요약

### 4.1 VD (Volume Descriptor) — `CONFIRMED` (WS78/79)

위치: LBA 1056 (VMA+0), 1 sector

```
+0x00  시그니처     \0MD001 + Version(0x01)
+0x10  디스크 파라미터  BlockSize, ClusterSize, AllocSize, NumAlloc, ...
+0x28  카운터       NumDefective, NumDir, NumFile, MaxIdNum, VolAttr
+0x3C  VMA 위치     VMALen, VMALoc, VSBLoc/Num, MTBLoc/Num, ERBLoc/Num, DRBLoc/Num
+0x54  디렉토리     DirLen, NumChild
+0x80+ 볼륨 라벨/타임스탬프 등
```

25 필드 + 4 패딩, 총 90 바이트 (0x00–0x59). 바이트 순서: **빅엔디안**.
9/9 교차 검증 통과.

### 4.2 VSB (Volume Space Bitmap) — `CONFIRMED` (WS80)

위치: LBA 1057–1059 (VMA+1..3), 3 sectors

```
인코딩: 2-bit per AU, MSB-first
  00 = FREE, 01 = USED, 10 = DEFECTIVE, 11 = RESERVED

1 byte = 4 AU, 1 sector = 8,192 AU
VSBNum = ceil(NumAlloc / 8192) = 3

VSB[0]: AU 0–8191     (LBA 1057)
VSB[1]: AU 8192–16383  (LBA 1058)
VSB[2]: AU 16384–17615 (LBA 1059, 유효 1232 AU + 패딩 0xFF)
```

AU 상태 읽기: `state = (vsb[au/4] >> ((3 - au%4) * 2)) & 0x03`
VD 4개 카운터 전부 일치 (5/5 match).

### 4.3 MTB (Management Table Block) — `CONFIRMED` (WS81)

위치: LBA 1060 (VMA+4), 1 sector

```
TLV 포맷: 4-byte 레코드 [tag(1B) + value(BE24, 3B)]
  0x80 = START (value=0)
  0x90 = DATA  (VSB 섹터별 FREE AU 수)
  0xA0 = END   (value=0)

DATA 엔트리 수 = VSBNum (3)
DATA 값 합계 = NumAvailable (7664+8192+1232 = 17088)
TRAILER: [0x00 0x00 0x00 0x02] — 의미 UNKNOWN
```

5/5 교차 검증 통과.

### 4.4 ERB (Error Record Block) — `UNKNOWN` (WS83)

테스트 미디어에 미할당 (ERBLoc=0, ERBNum=0, NumDefective=0).

역할 추정: 결함 AU 추적 테이블 (INFERRED).
내부 구조: 완전히 UNKNOWN — 결함 AU가 있는 디스크 필요.

FUSE 우회: VSB DEFECTIVE 상태(10)로 결함 AU 감지 → EIO 반환.

### 4.5 DRB (Directory Record Block) — `CONFIRMED`/`INFERRED` (WS82)

위치: LBA 1061 (VMA+5), 1 sector

```
가변 길이 레코드 (byte[1] = RecLen):

+0x00 [1B]  RecType     레코드 타입 (0x00)              CONFIRMED
+0x01 [1B]  RecLen      레코드 길이                     CONFIRMED
+0x02 [2B]  Attributes  속성 플래그 (BE16)              CONFIRMED
+0x04 [1B]  EntryType   0x02=dir, 0x01=file            INFERRED
+0x05 [1B]  Unknown05                                  UNKNOWN
+0x06 [10B] FileName    7+3, 공백 패딩                  CONFIRMED
+0x10 [4B]  CreateTime  Unix UTC (BE32)                CONFIRMED
+0x14 [4B]  ModifyTime  Unix UTC (BE32)                CONFIRMED
+0x18 [4B]  AccessTime  Unix UTC (BE32)                CONFIRMED
+0x1C [4B]  EntryID     (BE32)                         INFERRED
+0x20 [4B]  DataSize    bytes (BE32)                   CONFIRMED
+0x24 [2B]  DRBLoc/0    dir: DRBLoc, file: 0           INFERRED
+0x26 [2B]  DRBNum/SAU  dir: DRBNum, file: StartAU     INFERRED
+0x28 [2B]  Unknown28   (항상 0)                        UNKNOWN
확장:
+0x2A [2B]  ExtentAUCnt AU 수 (BE16)                   CONFIRMED
+0x2C [14B] (미사용)                                   UNKNOWN
```

테스트 미디어 엔트리:
- Entry 0: root directory (RecLen=42, Attr=0x0301=ADIR|AINHDELETE|AINHRENAME)
- Entry 1: Z920.EXE (RecLen=58, Attr=0x0040=APROTECT, StartAU=392, 136 AU)

8/8 교차 검증 통과.

## 5. AU 관점 전체 디스크 레이아웃

```
AU 범위          AU수     LBA 범위          VSB상태     내용
──────────────  ──────  ────────────────  ──────────  ─────────────────
AU     0–  255     256  LBA     0– 1023  RESERVED    Lead-in 영역
AU   256–  263       8  LBA  1024– 1055  USED        Pre-VMA (zeros)
AU   264–  265       2  LBA  1056– 1063  USED        VMA 관리 영역
AU   266–  391     126  LBA  1064– 1567  USED        VMA 예약 공간
AU   392–  527     136  LBA  1568– 2111  USED        Z920.EXE 파일 데이터
AU   528–17615  17,088  LBA  2112–70463  FREE        미할당 (사용 가능)
──────────────  ──────  ────────────────  ──────────  ─────────────────
합계            17,616                               = NumAlloc
```

카운터 대조:

| 상태 | AU 수 | VD 필드 | 일치 |
|------|-------|---------|------|
| RESERVED | 256 | NumAlloc − NumUsed − NumAvailable = 256 | ✓ |
| USED | 272 | NumUsed = 272 | ✓ |
| FREE | 17,088 | NumAvailable = 17,088 | ✓ |
| DEFECTIVE | 0 | NumDefective = 0 | ✓ |
| **합계** | **17,616** | **NumAlloc = 17,616** | ✓ |

## 6. 블록 간 참조 관계

```
                      ┌─────────────────────┐
                      │         VD          │
                      │  (위치/크기 총괄)    │
                      └──┬──┬──┬──┬──┬──────┘
                         │  │  │  │  │
              VSBLoc/Num │  │  │  │  │ DRBLoc/Num
                  ┌──────┘  │  │  │  └──────┐
                  ▼         │  │  │         ▼
             ┌────────┐    │  │  │    ┌────────┐
             │  VSB   │    │  │  │    │  DRB   │
             │(비트맵)│    │  │  │    │(디렉토리)│
             └───┬────┘    │  │  │    └────┬───┘
                 │    MTBLoc│  │ERBLoc     │
                 │         ▼  ▼           │
                 │    ┌────┐  ┌────┐      │ StartAU
                 │    │MTB │  │ERB │      │
                 │    │(요약)│ │(결함)│     │
                 │    └──┬─┘  └────┘      │
                 │       │                │
    VSB 섹터별   │ FREE AU│                │ 파일 위치
    AU 상태      │ 카운트 │                │
                 ▼       ▼                ▼
             ┌────────────────────────────────┐
             │        AU 데이터 영역          │
             │  (파일 데이터, 디렉토리 등)     │
             └────────────────────────────────┘
```

- **VD → VSB/MTB/ERB/DRB**: Loc/Num 쌍으로 블록 위치 지정
- **VSB ← → MTB**: MTB의 각 DATA 값 = 해당 VSB 섹터의 FREE AU 수 (역참조)
- **DRB → AU 데이터**: StartAU(+0x26)로 파일 데이터 위치 지정
- **DRB → DRB**: 디렉토리의 +0x24/+0x26이 하위 DRB 섹터 참조 (INFERRED)
- **VSB ← ERB**: ERB는 DEFECTIVE 상태 AU의 상세 정보 (INFERRED, UNKNOWN)
- **VD ← VSB/MTB/DRB**: NumUsed/NumAvailable/NumDefective 등 카운터 동기화

## 7. 교차 검증 집계 (11/11)

| # | 검증 항목 | 기대값 | 실측값 | 근거 |
|---|----------|--------|--------|------|
| 1 | NumAlloc×AllocSize×BlockSize | READ CAPACITY | 144,310,272 | WS78 |
| 2 | NumUsed+NumAvailable+Reserved | NumAlloc | 17,616 | WS79/80 |
| 3 | VSB FREE count | NumAvailable | 17,088 | WS80 |
| 4 | VSB USED count | NumUsed | 272 | WS80 |
| 5 | MTB DATA sum | NumAvailable | 17,088 | WS81 |
| 6 | MTB entry count | VSBNum | 3 | WS81 |
| 7 | DRB entry count | NumDir+NumFile | 2 | WS82 |
| 8 | Root DataSize | DirLen | 2,048 | WS82 |
| 9 | Z920 StartAU→MZ header | MZ at LBA 1568 | 확인 | WS82 |
| 10 | Z920 ExtentAUCnt | ceil(1110476/8192) | 136 | WS82 |
| 11 | max(EntryID) | MaxIdNum | 16 | WS82 |

**11/11 ALL PASS** — VMA 영역 전체 구조의 일관성 확인.

## 8. 분석 상태 요약

| 블록 | 상태 | 근거 WS | 핵심 내용 |
|------|------|---------|----------|
| VD | `CONFIRMED` | WS78/79 | 25필드+4패딩, 90바이트, 9/9 교차 검증 |
| VSB | `CONFIRMED` | WS80 | 2-bit/AU MSB-first, 4상태, 5/5 교차 검증 |
| MTB | `CONFIRMED` | WS81 | TLV [tag+BE24], FREE AU 카운트, 5/5 교차 검증 |
| ERB | `UNKNOWN` | WS83 | 데이터 없음, 역할만 INFERRED (결함 AU 테이블) |
| DRB | `CONFIRMED`/`INFERRED` | WS82 | 가변 길이 레코드, 14필드, 8/8 교차 검증 |

## 9. 잔여 미해결 사항

### FUSE 마운트에 영향 없음 (단일 디스크 기준)
- ERB 내부 구조 (NumDefective=0이면 불필요)
- MTB TRAILER 값 의미
- DRB +0x05, +0x28 필드

### FUSE 마운트에 잠재적 영향
- DRB +0x24/+0x26 이중 해석 확정 (서브디렉토리 있는 디스크 필요)
- DRB 확장 슬롯 구조 (fragmented 파일 필요)
- AFXTREC/AAEXTREC 익스텐트 체인 메커니즘

### 다중 디스크 / 결함 디스크 필요
- ERB 내부 레코드 구조
- DRB EntryID 할당 규칙
- 삭제 파일(ADELETED) 레코드 처리
- MTB TRAILER 값 disambiguation

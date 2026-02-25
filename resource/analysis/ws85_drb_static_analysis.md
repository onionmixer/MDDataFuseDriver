# WS85 DRB 미확인 필드 mdfsck 정적 분석

Date: 2026-02-24
Source: mdfsck.exe (w31/extract/mdfsck.exe) 역어셈블리 + DRB 바이너리 검증
Method: capstone 16-bit 역어셈블리 5라운드, printf 포맷 문자열 추출, raw 데이터 교차 검증

## 1. 개요

WS82에서 INFERRED/UNKNOWN으로 남은 DRB 필드를 mdfsck 바이너리 정적 분석으로 해결.
핵심: **byte-swap 함수(0x1672)의 두 경로**, **verbose 출력 포맷 문자열**, **extent 체인 분석 함수(0x2620)** 분석.

## 2. 핵심 발견

### 2.1 mdfsck 필드 이름 (포맷 문자열 추출)

mdfsck 바이너리 데이터 영역에서 추출한 DRB 레코드 필드명:

```
공통 필드:
  RLen=%-3d         RecLen (byte[1])
  Attr=             Attributes (BE16, +0x02)
  CSC=%-03d         Classification Code (byte, +0x04)
  ID=%-5d           EntryID (BE32, +0x1C)
  NLen=%-3d         Name Length/Type (byte, +0x05 추정)

디렉토리 전용:
  DLen=%-10ld       Data Length = DataSize (BE32, +0x20)
  DLoc=%-10d        Directory child DRB Location (BE16, +0x24)
  CNum=%-10d        Children DRB sector count (BE16, +0x26)

파일 전용:
  FLen=%-10ld       File Length = DataSize (BE32, +0x20)
  FLoc=%-10ld       F-extent Location (BE32, +0x24)
  FNum=%-10ld       F-extent AU count (BE32, +0x28)
  ALen=%-10ld       A-extent data Length (BE32, +0x2C)  ← NEW
  ALoc=%-10ld       A-extent Location (BE32, +0x30)     ← RENAMED
  ANum=%-10ld       A-extent AU count (BE32, +0x34)     ← RENAMED
```

추가 발견:
```
  FExtent: Loc=%ld Num=%ld    Fixed Extent chain entry format
  AExtent: Loc=%ld Num=%ld    Additional Extent chain entry format
  Extent Record Block: %d     외부 익스텐트 레코드 블록
  ERB Unused=%d Next=%d       ERB에 next 포인터/unused 카운터 존재
```

**근거**: mdfsck.exe 파일 오프셋 0xf24c-0xf338에서 순차 배치된 포맷 문자열 추출.

### 2.2 Byte-Swap 함수 분석 (0x1672) — 레코드 타입별 필드 크기 확정

함수 0x1672는 ADIR 플래그에 따라 **두 경로**로 분기:

```
입력: [bp+0xa] = ADIR 플래그 (1=디렉토리, 0=파일)
확인 코드 (0x1b24-0x1b28):
  mov ah, [0x6433]    ; record+3 raw byte (BE attr low byte)
  and ax, 0x100       ; test bit 0 of record[3] = ADIR flag
```

**경로 1 — 디렉토리 (ADIR=1):**
```
Swap 대상     크기     역할
──────────   ──────   ─────────────
+0x00        BE16     RecType|RecLen
+0x02        BE16     Attributes
+0x10-0x12   BE32     CreateTime
+0x14-0x16   BE32     ModifyTime
+0x18-0x1a   BE32     AccessTime
+0x1C-0x1E   BE32     EntryID
+0x20-0x22   BE32     DataSize (DLen)
+0x24        BE16     DLoc
+0x26        BE16     CNum
───── NO SWAP ─────
+0x04        byte     CSC (endian 무관)
+0x05        byte     NLen (endian 무관)
+0x06-0x0F   bytes    FileName (문자열)
+0x28-0x29   bytes    미스왑 (byte 필드)
```

**경로 2 — 파일 (ADIR=0):**
```
Swap 대상     크기     역할
──────────   ──────   ─────────────
+0x00        BE16     RecType|RecLen
+0x02        BE16     Attributes
+0x10-0x12   BE32     CreateTime
+0x14-0x16   BE32     ModifyTime
+0x18-0x1a   BE32     AccessTime
+0x1C-0x1E   BE32     EntryID
+0x20-0x22   BE32     DataSize (FLen)
+0x24-0x26   BE32     FLoc           ← 디렉토리와 다름!
+0x28-0x2A   BE32     FNum
+0x2C-0x2E   BE32     ALen
+0x30-0x32   BE32     ALoc
+0x34-0x36   BE32     ANum
───── NO SWAP ─────
+0x04        byte     CSC
+0x05        byte     NLen
+0x06-0x0F   bytes    FileName
+0x38-0x39   bytes    미스왑
```

**핵심 차이: +0x24-0x26은 디렉토리에서 2개의 BE16, 파일에서 1개의 BE32.**

### 2.3 CSC 필드 (+0x04) 해석

WS82에서 "EntryType"으로 INFERRED한 필드. mdfsck 이름: **CSC** (Classification Code 추정).

```
값    의미        근거
───  ─────────  ──────────────────────
0x01  파일        Z920.EXE: CSC=0x01
0x02  디렉토리   Root: CSC=0x02
```

코드 확인:
```asm
; 0x1df2 (verbose 출력)
1eac: mov al, byte ptr es:[bx + 4]   ; +0x04 = CSC, byte 접근
1eb0: push ax
1eb5: lcall printf                     ; "CSC=%-03d"
```

**상태: CONFIRMED** (mdfsck 코드 + 포맷 문자열 + 바이너리 데이터)

### 2.4 NLen 필드 (+0x05) 해석

WS82에서 "Unknown05"로 UNKNOWN한 필드. mdfsck 이름: **NLen** (Name Length).

```
엔트리      +0x05 값    해석
──────────  ────────   ─────────────
Root        0x01       표준 이름 (7+3)
Z920.EXE    0x37=55    ???
```

코드 확인:
```asm
; 0x1e15 (verbose 출력)
1e15: cmp byte ptr es:[bx + 5], 1    ; NLen == 1?
1e1a: je  0x1e48                      ; 1이면 표준 7+3 이름
; NLen != 1이면 다른 이름 처리 경로
1e1c: push 8
1e1e: lea  ax, [bx + 5]              ; +0x05부터 8바이트 복사
```

- NLen=1: 표준 7+3 이름 (공백 패딩, +0x06에서 시작)
- NLen≠1: 대안 이름 형식 (8+3, +0x05 자체가 이름 시작)

Z920.EXE의 NLen=55(0x37)은 표준 7+3이 아닌 대안 형식으로 판단되나,
실제 파일명은 "Z920   EXE"로 표준 형식과 동일하게 읽힘.
**정확한 의미는 추가 테스트 미디어 필요. 일단 NLen=1이면 표준 7+3으로 처리.**

**상태: INFERRED** (코드 확인, 의미 부분 확정)

### 2.5 +0x24/+0x26 이중 해석 — CONFIRMED

WS82에서 INFERRED한 DRB +0x24/+0x26 이중 해석이 byte-swap 함수로 **확정**:

```
디렉토리: +0x24 = DLoc (BE16), +0x26 = CNum (BE16) — 개별 16비트 스왑
파일:     +0x24/+0x26 = FLoc (BE32) — 단일 32비트 스왑
```

실제 데이터 검증:
```
Root:     DLoc=5 → VMA+5 = LBA 1061 (= DRBLoc, 자기 참조)
          CNum=1 → 1 DRB 섹터
Z920:     FLoc=392 → LBA 1568 (= AU 392 × 4)  ✓
```

**상태: CONFIRMED** (byte-swap 함수 경로 분기 + 데이터 검증)

### 2.6 파일 익스텐트 구조 (FLoc/FNum/ALen/ALoc/ANum)

WS82에서 +0x2A만 ExtentAUCnt로 확인했던 것이 완전 해명:

```
+0x24  FLoc (BE32)  F-extent 위치 (StartAU 또는 Extent Record 포인터)
+0x28  FNum (BE32)  F-extent AU 수 (136 = ceil(1110476/8192))
+0x2C  ALen (BE32)  A-extent 데이터 크기 (추가 데이터)
+0x30  ALoc (BE32)  A-extent 위치
+0x34  ANum (BE32)  A-extent AU 수
+0x38  byte         미확인 (0x00)
+0x39  byte         미확인 (0x00)
```

Z920.EXE 검증:
```
+0x24  FLoc = 0x00000188 = 392  → LBA 1568     ✓ (MZ 헤더 확인)
+0x28  FNum = 0x00000088 = 136  → ceil(1110476/8192) = 136  ✓
+0x2C  ALen = 0x00000000 = 0    → A-extent 없음  ✓
+0x30  ALoc = 0x00000000 = 0    → A-extent 없음  ✓
+0x34  ANum = 0x00000000 = 0    → A-extent 없음  ✓
+0x38  0x00                      → 의미 미확정
+0x39  0x00                      → 의미 미확정
```

**WS82 보정:**
- WS82의 +0x26 "StartAU (BE16)" → 실제는 **FLoc BE32의 하위 16비트** (상위 16비트가 0이어서 BE16처럼 보였음)
- WS82의 +0x2A "ExtentAUCnt (BE16)" → 실제는 **FNum BE32의 하위 16비트**
- +0x2C-0x36: WS82에서 "미사용 14바이트"로 판단 → 실제는 **ALen/ALoc/ANum (3개 BE32)**

### 2.7 AFXTREC/AAEXTREC 익스텐트 체인 메커니즘

코드 분석 (0x22b8-0x2594):

```
AFXTREC (attr bit 14, 0x4000):
  0x22b8: test byte [bx+3], 0x40     ; AFXTREC 테스트
  설정됨 → FLoc는 Extent Record Block 포인터 (0x2620으로 체인 추적)
  미설정 → FLoc/FNum은 인라인 익스텐트 (직접 AU 참조)

AAEXTREC (attr bit 15, 0x8000):
  0x24a9: test byte [bx+3], 0x80     ; AAEXTREC 테스트
  설정됨 → ALoc는 Extent Record Block 포인터 (0x2620으로 체인 추적)
  미설정 → ALoc/ANum은 인라인 익스텐트
```

Extent 체인 함수 (0x2620):
```
AEXT32 (VolAttr bit 15, 0x8000) 플래그에 따른 디코딩:

AEXT32 미설정 (우리 테스트 미디어):
  extent_sector = loc_value >> 6
  extent_offset = loc_value & 0x3F

AEXT32 설정:
  extent_sector = loc_hi_word
  extent_offset = loc_lo_word
```

Extent 테이블 엔트리 크기 (0x147e):
```
AEXT32 미설정: 0x20 (32) 바이트/엔트리 (Loc=BE16, Num=BE16)
AEXT32 설정:   0x40 (64) 바이트/엔트리 (Loc=BE32, Num=BE32)
```

**재귀 체인**: 함수 0x2620은 `cmp si, 8; jge exit` (최대 8단계)로 재귀 호출 (0x29ce).
→ 최대 8단계 깊이의 익스텐트 체인 지원.

### 2.8 AEXT32 레코드 포맷 결정

```asm
; 0x147e-0x148e
147e: mov bh, [0x5b69]     ; VolAttr high byte
1482: and bx, 0x8000       ; AEXT32 flag
1486: cmp bx, 1            ; 0 < 1 → carry, 0x8000 > 1 → no carry
1489: sbb si, si           ; si = 0xFFFF (AEXT32=0) or 0 (AEXT32=1)
148b: and si, 0x20          ; si = 0x20 or 0
148e: add si, 0x20          ; si = 0x40 or 0x20
```

테스트 미디어: VolAttr=0x0082, AEXT32 미설정 → 64-byte 익스텐트 엔트리.

### 2.9 디렉토리 레코드 +0x28 / 파일 레코드 +0x38

두 필드 모두 verbose 출력에서 **단일 바이트**로 읽힘:

```asm
; 디렉토리 경로 (0x1ee2)
1ee2: mov al, byte ptr es:[bx + 0x28]  ; dir +0x28 = byte

; 파일 경로 (0x1f44)
1f44: mov al, byte ptr es:[bx + 0x38]  ; file +0x38 = byte
```

테스트 미디어에서 두 값 모두 0x00.
의미 미확정 — 추가 테스트 미디어 필요.

### 2.10 MTB TRAILER

MTB 관련 코드(0x0f1f-0x131c)에서 TRAILER(tag=0x00, value=2)의 의미는 확정 불가.
코드에서 MTBLoc/MTBNum 참조 16곳 확인. 검증 루프에서 ERBLoc과 함께 사용되지만
TRAILER 값의 명시적 해석은 발견되지 않음.

### 2.11 ERB 관련 문자열 발견

```
"ERB Unused=%d Next=%d"  → ERB에 Unused 카운터 + Next 포인터 존재
```

이는 ERB가 연결 리스트 구조일 수 있음을 시사 (INFERRED).
NumDefective=0인 테스트 미디어에서는 여전히 실데이터 확인 불가.

## 3. 완성된 DRB 레코드 구조

### 3.1 공통 헤더 (디렉토리/파일 공유, 36바이트)

```
오프셋  크기    필드        형식      상태          설명
──────  ──────  ──────────  ──────  ──────────  ──────────────────────
+0x00   1B      RecType     byte    CONFIRMED   레코드 타입 (0x00)
+0x01   1B      RecLen      byte    CONFIRMED   레코드 전체 길이
+0x02   2B      Attributes  BE16    CONFIRMED   속성 플래그
+0x04   1B      CSC         byte    CONFIRMED   분류 코드 (0x02=dir, 0x01=file)
+0x05   1B      NLen        byte    INFERRED    이름 길이/타입 (1=표준 7+3)
+0x06   10B     FileName    7+3     CONFIRMED   파일명 (공백 패딩)
+0x10   4B      CreateTime  BE32    CONFIRMED   생성 시간 (Unix UTC)
+0x14   4B      ModifyTime  BE32    CONFIRMED   수정 시간
+0x18   4B      AccessTime  BE32    CONFIRMED   접근 시간
+0x1C   4B      EntryID     BE32    CONFIRMED   엔트리 ID
+0x20   4B      DataSize    BE32    CONFIRMED   데이터 크기 (DLen/FLen)
```

### 3.2 디렉토리 확장 (6바이트, RecLen=42)

```
오프셋  크기    필드    형식    상태          설명
──────  ──────  ──────  ──────  ──────────  ──────────────────────
+0x24   2B      DLoc    BE16    CONFIRMED   하위 DRB 위치 (VMA 상대)
+0x26   2B      CNum    BE16    CONFIRMED   하위 DRB 섹터 수
+0x28   1B      ???     byte    UNKNOWN     미확인 (0x00)
+0x29   1B      (pad)   byte    UNKNOWN     패딩 (0x00)
```

### 3.3 파일 확장 (22바이트, RecLen=58)

```
오프셋  크기    필드    형식    상태          설명
──────  ──────  ──────  ──────  ──────────  ──────────────────────
+0x24   4B      FLoc    BE32    CONFIRMED   F-extent 위치 (StartAU)
+0x28   4B      FNum    BE32    CONFIRMED   F-extent AU 수
+0x2C   4B      ALen    BE32    CONFIRMED   A-extent 데이터 크기
+0x30   4B      ALoc    BE32    CONFIRMED   A-extent 위치
+0x34   4B      ANum    BE32    CONFIRMED   A-extent AU 수
+0x38   1B      ???     byte    UNKNOWN     미확인 (0x00)
+0x39   1B      (pad)   byte    UNKNOWN     패딩 (0x00)
```

### 3.4 Extent 해석 규칙

```
조건                          FLoc 해석        FNum 해석
────────────────────────────  ──────────────  ────────────────
AFXTREC=0 (인라인)            StartAU          AU 수
AFXTREC=1 (레코드 체인)       Extent Record    총 AU 수 (검증용)
                              Block 포인터

조건                          ALoc 해석        ANum 해석
────────────────────────────  ──────────────  ────────────────
AAEXTREC=0, ANum>0 (인라인)   StartAU          AU 수
AAEXTREC=1 (레코드 체인)      Extent Record    총 AU 수 (검증용)
                              Block 포인터
ANum=0 (A-extent 없음)        0                0
```

## 4. 교차 검증 (5/5 ALL PASS)

| # | 검증 항목 | 기대값 | 실측값 | 근거 |
|---|----------|--------|--------|------|
| 1 | FLoc → LBA | 392×4=1568 | MZ header at LBA 1568 | WS78+WS82 |
| 2 | FNum | ceil(1110476/8192)=136 | 136 | WS82 |
| 3 | DLoc | VD.DRBLoc=5 | Root DLoc=5 | self-reference ✓ |
| 4 | CNum | VD.DRBNum=1 | Root CNum=1 | VD 일치 ✓ |
| 5 | byte-swap 경로 분기 | ADIR → dir path | attr bit0 test ✓ | code 확인 |

## 5. WS82 보정 사항

| WS82 필드 | WS82 해석 | WS85 정정 | 근거 |
|-----------|----------|----------|------|
| +0x04 EntryType | 0x02=dir, 0x01=file (INFERRED) | CSC, 동일 값 **(CONFIRMED)** | 포맷 문자열 |
| +0x05 Unknown05 | UNKNOWN | NLen, 1=표준이름 **(INFERRED)** | 코드 분기 |
| +0x24/+0x26 dual | INFERRED | **CONFIRMED** (byte-swap 2경로) | 0x1672 분석 |
| +0x26 StartAU (BE16) | INFERRED | **FLoc BE32의 하위 16비트** | byte-swap 확인 |
| +0x2A ExtentAUCnt (BE16) | CONFIRMED | **FNum BE32의 하위 16비트** | byte-swap 확인 |
| +0x28 Unknown28 | UNKNOWN | 디렉토리: byte 필드; 파일: FNum 상위 16비트 | 타입별 분리 |
| +0x2C-0x39 (미사용 14B) | UNKNOWN | **ALen/ALoc/ANum + 2 bytes** | byte-swap + 문자열 |

## 6. 미해결 사항

### FUSE 마운트에 영향 없음 (테스트 미디어 기준)
- +0x28 (dir) / +0x38 (file) byte 필드 의미
- NLen (+0x05)의 정확한 의미 (NLen≠1인 이름 포맷)
- CSC "Classification Code" 전체 값 범위
- MTB TRAILER 값 의미

### FUSE 마운트에 잠재적 영향 (fragmented 파일)
- AFXTREC Extent Record Block 내부 구조 (fragmented 파일 필요)
- AAEXTREC A-extent 체인 메커니즘 (A-extent 있는 파일 필요)
- AEXT32 extent 엔트리 세부 포맷 (해당 VolAttr 디스크 필요)
- ALen/ALoc/ANum의 실제 사용 사례

### 추가 미디어 필요
- ERB 내부 구조 ("ERB Unused=%d Next=%d" 발견, 구조 미확정)
- NLen>1 이름 포맷
- 서브디렉토리 DRB 체인

## 7. FUSE 구현 사양

```rust
/// DRB 공통 헤더 (36 bytes)
struct DrbCommonHeader {
    rec_type: u8,       // +0x00, always 0x00
    rec_len: u8,        // +0x01
    attributes: u16,    // +0x02, BE16
    csc: u8,            // +0x04, 0x01=file, 0x02=dir
    nlen: u8,           // +0x05, 1=standard 7+3 name
    filename: [u8; 10], // +0x06, 7+3 space-padded
    create_time: u32,   // +0x10, BE32 Unix UTC
    modify_time: u32,   // +0x14, BE32
    access_time: u32,   // +0x18, BE32
    entry_id: u32,      // +0x1C, BE32
    data_size: u32,     // +0x20, BE32
}

/// 디렉토리 확장 (6 bytes)
struct DrbDirExt {
    dloc: u16,  // +0x24, BE16, VMA-relative DRB sector
    cnum: u16,  // +0x26, BE16, child DRB sector count
    _unk28: u8, // +0x28
    _pad: u8,   // +0x29
}

/// 파일 확장 (22 bytes)
struct DrbFileExt {
    floc: u32,  // +0x24, BE32, F-extent start AU or record ptr
    fnum: u32,  // +0x28, BE32, F-extent AU count
    alen: u32,  // +0x2C, BE32, A-extent data size
    aloc: u32,  // +0x30, BE32, A-extent start AU or record ptr
    anum: u32,  // +0x34, BE32, A-extent AU count
    _unk38: u8, // +0x38
    _pad: u8,   // +0x39
}

/// 속성 플래그 (BE16)
const ADIR:        u16 = 0x0001;
const AINVISIBLE:  u16 = 0x0002;
const ASYSTEM:     u16 = 0x0004;
const ADELETED:    u16 = 0x0008;  // CONFIRMED by 0x1b37
const APROTECT:    u16 = 0x0040;
const AINHDELETE:  u16 = 0x0100;
const AINHRENAME:  u16 = 0x0200;
const AINHCOPY:    u16 = 0x0400;
const AEXTTYPE:    u16 = 0x2000;  // CONFIRMED by 0x221e
const AFXTREC:     u16 = 0x4000;  // CONFIRMED by 0x22b8
const AAEXTREC:    u16 = 0x8000;  // CONFIRMED by 0x24a9

/// 파일 데이터 위치 해석
fn get_file_extents(rec: &DrbFileExt, attrs: u16) -> FileExtents {
    if attrs & AFXTREC != 0 {
        // FLoc → Extent Record Block 포인터
        FileExtents::ExtentRecord { ptr: rec.floc, total_aus: rec.fnum }
    } else {
        // FLoc → 직접 StartAU
        FileExtents::Inline { start_au: rec.floc, au_count: rec.fnum }
    }
}

/// A-extent 처리 (FUSE 초기 버전에서는 미지원)
fn get_additional_extents(rec: &DrbFileExt, attrs: u16) -> Option<AdditionalExtents> {
    if rec.anum == 0 && rec.aloc == 0 {
        return None;  // A-extent 없음
    }
    if attrs & AAEXTREC != 0 {
        Some(AdditionalExtents::ExtentRecord { ptr: rec.aloc, total_aus: rec.anum })
    } else {
        Some(AdditionalExtents::Inline { start_au: rec.aloc, au_count: rec.anum })
    }
}
```

## 8. 결론

mdfsck 정적 분석으로 DRB 레코드의 거의 모든 필드가 해명됨:

- **+0x04 (CSC)**: INFERRED → **CONFIRMED** (0x01=file, 0x02=dir)
- **+0x05 (NLen)**: UNKNOWN → **INFERRED** (1=표준 7+3, 기타=대안 포맷)
- **+0x24/+0x26 이중 해석**: INFERRED → **CONFIRMED** (byte-swap 분기)
- **파일 익스텐트 구조**: 부분 CONFIRMED → **완전 CONFIRMED** (5개 BE32 필드)
- **AFXTREC/AAEXTREC 메커니즘**: UNKNOWN → **INFERRED** (코드 흐름 확인)

잔여 UNKNOWN: +0x28(dir)/+0x38(file) byte 필드, NLen≠1 이름 포맷, MTB TRAILER.
이들은 단일 디스크 기준 FUSE 읽기전용 마운트에 영향 없음.

/*
 * mdfs.h — MDFS (Sony MD DATA File System) 온디스크 구조 및 라이브러리 API
 *
 * 근거: MDFS_SPEC_FINAL.md (WS78-85 CONFIRMED)
 * 바이트 순서: 온디스크 = 빅엔디안, 인메모리 = 호스트 엔디안
 */
#ifndef MDFS_H
#define MDFS_H

#include <stdint.h>
#include <stddef.h>

/* ===================================================================
 * 상수
 * =================================================================== */

#define MDFS_SECTOR_SIZE      2048
#define MDFS_IDENT            "MD001"
#define MDFS_IDENT_LEN        5

/* 기본 디스크 파라미터 (테스트 미디어 기준) */
#define MDFS_DEFAULT_BLOCK_SIZE    2048
#define MDFS_DEFAULT_CLUSTER_SIZE  32
#define MDFS_DEFAULT_ALLOC_SIZE    4    /* sectors per AU */
#define MDFS_AU_BYTES              (MDFS_DEFAULT_ALLOC_SIZE * MDFS_SECTOR_SIZE) /* 8192 */

/* AU 상태 (VSB 2-bit per AU, MSB-first) */
#define MDFS_AU_FREE          0
#define MDFS_AU_USED          1
#define MDFS_AU_DEFECTIVE     2
#define MDFS_AU_RESERVED      3

/* DRB 속성 플래그 (+0x02 BE16) */
#define MDFS_ATTR_ADIR        0x0001
#define MDFS_ATTR_AINVISIBLE  0x0002
#define MDFS_ATTR_ASYSTEM     0x0004
#define MDFS_ATTR_ADELETED    0x0008
#define MDFS_ATTR_APROTECT    0x0040
#define MDFS_ATTR_ABACKUP     0x0080
#define MDFS_ATTR_AINHDELETE  0x0100
#define MDFS_ATTR_AINHRENAME  0x0200
#define MDFS_ATTR_AINHCOPY    0x0400
#define MDFS_ATTR_AEXTTYPE    0x2000
#define MDFS_ATTR_AFXTREC     0x4000
#define MDFS_ATTR_AAEXTREC    0x8000

/* DRB CSC (Classification Code) */
#define MDFS_CSC_FILE         0x01
#define MDFS_CSC_DIR          0x02

/* MTB 태그 */
#define MDFS_MTB_START        0x80
#define MDFS_MTB_DATA         0x90
#define MDFS_MTB_END          0xA0

/* DRB 레코드 크기 */
#define MDFS_DRB_COMMON_SIZE  36   /* 공통 헤더 */
#define MDFS_DRB_DIR_MIN      42   /* 공통 + dir 확장 (6) */
#define MDFS_DRB_FILE_MIN     58   /* 공통 + file 확장 (22) */

/* 최대값 */
#define MDFS_MAX_NAME_LEN     10   /* 온디스크 이름 (7+3) */
#define MDFS_MAX_ENTRIES      4096 /* 디렉토리당 최대 엔트리 */
#define MDFS_VSB_AU_PER_SECTOR 8192 /* 2048 bytes × 4 AU/byte */

/* ===================================================================
 * 온디스크 구조체 (packed, 빅엔디안 그대로)
 * =================================================================== */

/* VD (Volume Descriptor) — 90 bytes at VMALoc sector */
typedef struct __attribute__((packed)) {
    uint8_t  rec_type;          /* +0x00: always 0 */
    char     ident[5];          /* +0x01: "MD001" */
    uint8_t  version;           /* +0x06 */
    uint8_t  reserved_07[9];    /* +0x07-0x0F */
    uint16_t block_size;        /* +0x10: BE16 */
    uint16_t cluster_size;      /* +0x12: BE16 */
    uint16_t alloc_size;        /* +0x14: BE16, sectors per AU */
    uint16_t reserved_16;       /* +0x16 */
    uint32_t num_alloc;         /* +0x18: BE32, total AU count */
    uint32_t num_recordable;    /* +0x1C: BE32 */
    uint32_t num_available;     /* +0x20: BE32 */
    uint32_t num_used;          /* +0x24: BE32 */
    uint32_t num_defective;     /* +0x28: BE32 */
    uint32_t reserved_2c;       /* +0x2C */
    uint16_t num_dir;           /* +0x30: BE16 */
    uint16_t num_file;          /* +0x32: BE16 */
    uint32_t max_id_num;        /* +0x34: BE32 */
    uint16_t vol_attr;          /* +0x38: BE16 */
    uint16_t reserved_3a;       /* +0x3A */
    uint32_t vma_len;           /* +0x3C: BE32 */
    uint32_t vma_loc;           /* +0x40: BE32, absolute sector */
    uint16_t vsb_loc;           /* +0x44: BE16, relative to vma_loc */
    uint16_t vsb_num;           /* +0x46: BE16 */
    uint16_t mtb_loc;           /* +0x48: BE16 */
    uint16_t mtb_num;           /* +0x4A: BE16 */
    uint16_t erb_loc;           /* +0x4C: BE16 */
    uint16_t erb_num;           /* +0x4E: BE16 */
    uint16_t drb_loc;           /* +0x50: BE16 */
    uint16_t drb_num;           /* +0x52: BE16 */
    uint32_t dir_len;           /* +0x54: BE32 */
    uint16_t num_child;         /* +0x58: BE16 */
} mdfs_vd_ondisk_t;

/* ===================================================================
 * 인메모리 구조체 (호스트 엔디안)
 * =================================================================== */

/* VD 인메모리 */
typedef struct {
    uint8_t  rec_type;
    char     ident[6];          /* null-terminated */
    uint8_t  version;
    uint16_t block_size;
    uint16_t cluster_size;
    uint16_t alloc_size;
    uint32_t num_alloc;
    uint32_t num_recordable;
    uint32_t num_available;
    uint32_t num_used;
    uint32_t num_defective;
    uint16_t num_dir;
    uint16_t num_file;
    uint32_t max_id_num;
    uint16_t vol_attr;
    uint32_t vma_len;
    uint32_t vma_loc;
    uint16_t vsb_loc;
    uint16_t vsb_num;
    uint16_t mtb_loc;
    uint16_t mtb_num;
    uint16_t erb_loc;
    uint16_t erb_num;
    uint16_t drb_loc;
    uint16_t drb_num;
    uint32_t dir_len;
    uint16_t num_child;
    /* 런타임 계산 */
    uint32_t au_bytes;          /* alloc_size * block_size */
} mdfs_vd_t;

/* DRB 인메모리 엔트리 */
typedef struct {
    uint8_t  rec_len;           /* 원본 RecLen */
    uint16_t attr;
    uint8_t  csc;               /* MDFS_CSC_FILE or MDFS_CSC_DIR */
    uint8_t  nlen;
    char     raw_name[10];      /* 온디스크 7+3 그대로 */
    char     name[13];          /* null-terminated "BASE.EXT" */
    uint32_t create_time;
    uint32_t modify_time;
    uint32_t access_time;
    uint32_t entry_id;
    uint32_t data_size;
    /* dir 확장 (csc == MDFS_CSC_DIR) */
    uint16_t dloc;              /* child DRB VMA-relative sector */
    uint16_t cnum;              /* child DRB sector count */
    /* file 확장 (csc == MDFS_CSC_FILE) */
    uint32_t floc;              /* F-extent StartAU or ERB ptr */
    uint32_t fnum;              /* F-extent AU count */
    uint32_t alen;              /* A-extent data size */
    uint32_t aloc;              /* A-extent location */
    uint32_t anum;              /* A-extent AU count */
} mdfs_entry_t;

/* ===================================================================
 * I/O 추상화
 * =================================================================== */

typedef struct mdfs_io mdfs_io_t;

mdfs_io_t *mdfs_io_open(const char *path, int readonly);
void       mdfs_io_close(mdfs_io_t *io);
int        mdfs_io_read_sector(mdfs_io_t *io, uint32_t lba, void *buf);
int        mdfs_io_write_sector(mdfs_io_t *io, uint32_t lba, const void *buf);
uint64_t   mdfs_io_size(mdfs_io_t *io);

/* ===================================================================
 * VD API
 * =================================================================== */

int  mdfs_vd_read(mdfs_io_t *io, uint32_t vd_lba, mdfs_vd_t *vd);
int  mdfs_vd_write(mdfs_io_t *io, uint32_t vd_lba, const mdfs_vd_t *vd);
int  mdfs_vd_validate(const mdfs_vd_t *vd);

/* VD 위치 탐색: LBA 1056 고정 (테스트 미디어 기준) 또는 스캔 */
uint32_t mdfs_vd_find(mdfs_io_t *io);

/* ===================================================================
 * VSB API
 * =================================================================== */

int  mdfs_vsb_get_state(mdfs_io_t *io, const mdfs_vd_t *vd, uint32_t au);
int  mdfs_vsb_set_state(mdfs_io_t *io, const mdfs_vd_t *vd, uint32_t au, int state);

/* AU 할당: 첫 FREE AU 찾아 USED로 설정, *out_au에 반환 */
int  mdfs_vsb_alloc(mdfs_io_t *io, mdfs_vd_t *vd, uint32_t *out_au);
/* 연속 n개 AU 할당 시도 */
int  mdfs_vsb_alloc_contiguous(mdfs_io_t *io, mdfs_vd_t *vd, uint32_t n, uint32_t *out_start);
/* AU 해제: USED→FREE */
int  mdfs_vsb_free(mdfs_io_t *io, mdfs_vd_t *vd, uint32_t au);

/* ===================================================================
 * MTB API
 * =================================================================== */

/* MTB 읽기: counts[i] = VSB sector i의 FREE AU 수, *n = entry count */
int  mdfs_mtb_read(mdfs_io_t *io, const mdfs_vd_t *vd, uint32_t *counts, int *n);
/* MTB 재구축: VSB에서 FREE count 재계산하여 MTB 덮어쓰기 */
int  mdfs_mtb_rebuild(mdfs_io_t *io, const mdfs_vd_t *vd);

/* ===================================================================
 * DRB API
 * =================================================================== */

/* 디렉토리의 DRB 섹터에서 엔트리 목록 읽기 */
int  mdfs_drb_read(mdfs_io_t *io, const mdfs_vd_t *vd,
                   uint32_t drb_lba, uint16_t drb_num,
                   mdfs_entry_t *entries, int *count, int max_entries);

/* 디렉토리에 DRB 엔트리 쓰기 */
int  mdfs_drb_write(mdfs_io_t *io, const mdfs_vd_t *vd,
                    uint32_t drb_lba, uint16_t drb_num,
                    const mdfs_entry_t *entries, int count);

/* ===================================================================
 * Extent / 데이터 접근 API
 * =================================================================== */

/* AU→LBA 변환 */
static inline uint32_t mdfs_au_to_lba(const mdfs_vd_t *vd, uint32_t au) {
    return au * vd->alloc_size;
}

/* 파일 데이터 읽기 (오프셋/길이 기반) */
int  mdfs_data_read(mdfs_io_t *io, const mdfs_vd_t *vd,
                    const mdfs_entry_t *entry,
                    uint64_t offset, void *buf, size_t len, size_t *bytes_read);

/* 파일 데이터 쓰기 */
int  mdfs_data_write(mdfs_io_t *io, mdfs_vd_t *vd,
                     mdfs_entry_t *entry,
                     uint64_t offset, const void *buf, size_t len, size_t *bytes_written);

/* ===================================================================
 * 유틸리티
 * =================================================================== */

/* 이름 변환: "BASE   EXT" (10바이트) → "BASE.EXT" (null-terminated) */
void mdfs_name_decode(const char raw[10], char out[13]);
/* 역변환: "BASE.EXT" → "BASE   EXT" (10바이트, 공백패딩) */
int  mdfs_name_encode(const char *str, char raw[10]);

/* 엔디안 변환 */
uint16_t mdfs_be16(uint16_t v);
uint32_t mdfs_be32(uint32_t v);

/* 에러 코드 */
#define MDFS_OK          0
#define MDFS_ERR_IO     -1
#define MDFS_ERR_INVAL  -2
#define MDFS_ERR_NOSPC  -3
#define MDFS_ERR_NOENT  -4
#define MDFS_ERR_CORRUPT -5

#endif /* MDFS_H */

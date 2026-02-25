/*
 * extent.c — 파일 데이터 접근 (AU 기반 extent → LBA → sector read/write)
 *
 * 현재: 단일 익스텐트 (AFXTREC/AAEXTREC 미설정) 만 지원
 * AFXTREC/AAEXTREC 설정된 파일은 에러 반환
 */
#include "mdfs.h"
#include <string.h>

int mdfs_data_read(mdfs_io_t *io, const mdfs_vd_t *vd,
                   const mdfs_entry_t *entry,
                   uint64_t offset, void *buf, size_t len, size_t *bytes_read)
{
    *bytes_read = 0;

    if (entry->csc != MDFS_CSC_FILE)
        return MDFS_ERR_INVAL;

    /* 외부 익스텐트 레코드 미지원 */
    if (entry->attr & MDFS_ATTR_AFXTREC)
        return MDFS_ERR_INVAL;

    if (offset >= entry->data_size)
        return MDFS_OK; /* EOF */

    /* 읽기 범위 클램핑 */
    if (offset + len > entry->data_size)
        len = (size_t)(entry->data_size - offset);

    uint32_t start_lba = mdfs_au_to_lba(vd, entry->floc);
    uint8_t *dst = (uint8_t *)buf;
    size_t remaining = len;

    while (remaining > 0) {
        /* 현재 위치의 섹터/오프셋 계산 */
        uint64_t file_pos = offset + (len - remaining);
        uint32_t sector_in_file = (uint32_t)(file_pos / MDFS_SECTOR_SIZE);
        uint32_t off_in_sector = (uint32_t)(file_pos % MDFS_SECTOR_SIZE);

        /* extent 범위 확인 */
        uint32_t max_sectors = entry->fnum * vd->alloc_size;
        if (sector_in_file >= max_sectors)
            break;

        uint8_t sector[MDFS_SECTOR_SIZE];
        int rc = mdfs_io_read_sector(io, start_lba + sector_in_file, sector);
        if (rc != MDFS_OK)
            return rc;

        size_t chunk = MDFS_SECTOR_SIZE - off_in_sector;
        if (chunk > remaining)
            chunk = remaining;

        memcpy(dst, sector + off_in_sector, chunk);
        dst += chunk;
        remaining -= chunk;
    }

    *bytes_read = len - remaining;
    return MDFS_OK;
}

int mdfs_data_write(mdfs_io_t *io, mdfs_vd_t *vd,
                    mdfs_entry_t *entry,
                    uint64_t offset, const void *buf, size_t len, size_t *bytes_written)
{
    *bytes_written = 0;

    if (entry->csc != MDFS_CSC_FILE)
        return MDFS_ERR_INVAL;

    if (entry->attr & MDFS_ATTR_AFXTREC)
        return MDFS_ERR_INVAL;

    /* 파일 확장이 필요한 경우 AU 추가 할당 */
    uint64_t end_pos = offset + len;
    uint32_t needed_bytes = (end_pos > entry->data_size) ? (uint32_t)end_pos : entry->data_size;
    uint32_t needed_au = (needed_bytes + vd->au_bytes - 1) / vd->au_bytes;

    if (needed_au > entry->fnum) {
        if (entry->fnum == 0) {
            /* 새 파일: AU 할당 */
            uint32_t start_au;
            int rc = mdfs_vsb_alloc_contiguous(io, vd, needed_au, &start_au);
            if (rc != MDFS_OK)
                return rc;
            entry->floc = start_au;
            entry->fnum = needed_au;
        } else {
            /* 기존 파일 확장 */
            uint32_t extra = needed_au - entry->fnum;

            /* 1차: 인접 AU 확장 시도 */
            uint32_t next_au = entry->floc + entry->fnum;
            int can_extend = 1;
            for (uint32_t i = 0; i < extra; i++) {
                if (next_au + i >= vd->num_alloc ||
                    mdfs_vsb_get_state(io, vd, next_au + i) != MDFS_AU_FREE) {
                    can_extend = 0;
                    break;
                }
            }

            if (can_extend) {
                for (uint32_t i = 0; i < extra; i++) {
                    int rc = mdfs_vsb_set_state(io, vd, next_au + i, MDFS_AU_USED);
                    if (rc != MDFS_OK)
                        return rc;
                    vd->num_used++;
                    vd->num_available--;
                }
                entry->fnum = needed_au;
            } else {
                /* 2차: 새 연속 블록 할당 → 데이터 복사 → 이전 블록 해제 */
                uint32_t new_start;
                int rc = mdfs_vsb_alloc_contiguous(io, vd, needed_au, &new_start);
                if (rc != MDFS_OK)
                    return rc;

                uint32_t old_lba = mdfs_au_to_lba(vd, entry->floc);
                uint32_t new_lba = mdfs_au_to_lba(vd, new_start);
                uint32_t sectors_to_copy = entry->fnum * vd->alloc_size;
                uint8_t sec[MDFS_SECTOR_SIZE];
                for (uint32_t s = 0; s < sectors_to_copy; s++) {
                    rc = mdfs_io_read_sector(io, old_lba + s, sec);
                    if (rc != MDFS_OK)
                        return rc;
                    rc = mdfs_io_write_sector(io, new_lba + s, sec);
                    if (rc != MDFS_OK)
                        return rc;
                }

                /* 이전 AU 해제 */
                uint32_t old_fnum = entry->fnum;
                for (uint32_t i = 0; i < old_fnum; i++)
                    mdfs_vsb_free(io, vd, entry->floc + i);

                entry->floc = new_start;
                entry->fnum = needed_au;
            }
        }
    }

    uint32_t start_lba = mdfs_au_to_lba(vd, entry->floc);
    const uint8_t *src = (const uint8_t *)buf;
    size_t remaining = len;

    while (remaining > 0) {
        uint64_t file_pos = offset + (len - remaining);
        uint32_t sector_in_file = (uint32_t)(file_pos / MDFS_SECTOR_SIZE);
        uint32_t off_in_sector = (uint32_t)(file_pos % MDFS_SECTOR_SIZE);

        uint8_t sector[MDFS_SECTOR_SIZE];

        /* 부분 섹터 쓰기: 기존 데이터 읽기 필요 */
        if (off_in_sector != 0 || remaining < MDFS_SECTOR_SIZE) {
            int rc = mdfs_io_read_sector(io, start_lba + sector_in_file, sector);
            if (rc != MDFS_OK)
                memset(sector, 0, MDFS_SECTOR_SIZE);
        }

        size_t chunk = MDFS_SECTOR_SIZE - off_in_sector;
        if (chunk > remaining)
            chunk = remaining;

        memcpy(sector + off_in_sector, src, chunk);

        int rc = mdfs_io_write_sector(io, start_lba + sector_in_file, sector);
        if (rc != MDFS_OK)
            return rc;

        src += chunk;
        remaining -= chunk;
    }

    *bytes_written = len - remaining;

    /* DataSize 업데이트 */
    if (end_pos > entry->data_size)
        entry->data_size = (uint32_t)end_pos;

    return MDFS_OK;
}

/*
 * mtb.c — MTB (Management Table Block) TLV 읽기/쓰기
 *
 * WS81 CONFIRMED: 4-byte TLV [tag(1B) + value(BE24)]
 * tag 0x80=START, 0x90=DATA (per-VSB FREE count), 0xA0=END
 */
#include "mdfs.h"
#include <string.h>

/* BE24 읽기 */
static uint32_t read_be24(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}

/* BE24 쓰기 */
static void write_be24(uint8_t *p, uint32_t val)
{
    p[0] = (uint8_t)(val >> 16);
    p[1] = (uint8_t)(val >> 8);
    p[2] = (uint8_t)(val);
}

int mdfs_mtb_read(mdfs_io_t *io, const mdfs_vd_t *vd, uint32_t *counts, int *n)
{
    if (vd->mtb_num == 0)
        return MDFS_ERR_INVAL;

    uint8_t sector[MDFS_SECTOR_SIZE];
    uint32_t mtb_lba = vd->vma_loc + vd->mtb_loc;
    int rc = mdfs_io_read_sector(io, mtb_lba, sector);
    if (rc != MDFS_OK)
        return rc;

    int idx = 0;
    *n = 0;

    /* START 태그 확인 */
    if (sector[0] != MDFS_MTB_START)
        return MDFS_ERR_CORRUPT;
    idx = 4;

    /* DATA 태그 읽기 */
    while (idx + 4 <= MDFS_SECTOR_SIZE) {
        uint8_t tag = sector[idx];
        if (tag == MDFS_MTB_END)
            break;
        if (tag != MDFS_MTB_DATA)
            return MDFS_ERR_CORRUPT;

        if (*n < (int)vd->vsb_num) {
            counts[*n] = read_be24(sector + idx + 1);
            (*n)++;
        }
        idx += 4;
    }

    return MDFS_OK;
}

int mdfs_mtb_rebuild(mdfs_io_t *io, const mdfs_vd_t *vd)
{
    uint8_t sector[MDFS_SECTOR_SIZE];
    memset(sector, 0, MDFS_SECTOR_SIZE);

    int idx = 0;

    /* START */
    sector[idx] = MDFS_MTB_START;
    write_be24(sector + idx + 1, 0);
    idx += 4;

    /* DATA: per-VSB-sector FREE count */
    for (uint32_t si = 0; si < vd->vsb_num; si++) {
        uint32_t free_count = 0;
        uint32_t base_au = si * MDFS_VSB_AU_PER_SECTOR;

        /* VSB 섹터 읽기 */
        uint8_t vsb_sector[MDFS_SECTOR_SIZE];
        uint32_t vsb_lba = vd->vma_loc + vd->vsb_loc + si;
        if (mdfs_io_read_sector(io, vsb_lba, vsb_sector) != MDFS_OK)
            return MDFS_ERR_IO;

        for (uint32_t b = 0; b < MDFS_SECTOR_SIZE; b++) {
            for (int bit = 3; bit >= 0; bit--) {
                uint32_t au = base_au + b * 4 + (3 - bit);
                if (au >= vd->num_alloc)
                    break;
                int st = (vsb_sector[b] >> (bit * 2)) & 0x03;
                if (st == MDFS_AU_FREE)
                    free_count++;
            }
        }

        sector[idx] = MDFS_MTB_DATA;
        write_be24(sector + idx + 1, free_count);
        idx += 4;
    }

    /* END */
    sector[idx] = MDFS_MTB_END;
    write_be24(sector + idx + 1, 0);
    idx += 4;

    /* TRAILER (의미 미확정 — entry count 기록) */
    sector[idx] = 0x00;
    write_be24(sector + idx + 1, vd->num_dir + vd->num_file);

    uint32_t mtb_lba = vd->vma_loc + vd->mtb_loc;
    return mdfs_io_write_sector(io, mtb_lba, sector);
}

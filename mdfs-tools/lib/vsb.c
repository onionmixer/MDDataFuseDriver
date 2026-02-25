/*
 * vsb.c — VSB (Volume Space Bitmap) 2-bit/AU 비트맵 읽기/쓰기
 *
 * WS80 CONFIRMED: 2-bit per AU, MSB-first
 * 1 byte = 4 AU: bit7-6=AU₀, bit5-4=AU₁, bit3-2=AU₂, bit1-0=AU₃
 * state = (vsb[au/4] >> ((3 - au%4) * 2)) & 0x03
 */
#include "mdfs.h"
#include <string.h>

/* VSB 섹터 내 AU 위치 계산 */
static int vsb_locate(const mdfs_vd_t *vd, uint32_t au,
                      uint32_t *out_lba, uint32_t *out_byte, int *out_shift)
{
    if (au >= vd->num_alloc)
        return MDFS_ERR_INVAL;

    uint32_t vsb_sector_idx = au / MDFS_VSB_AU_PER_SECTOR;
    uint32_t au_in_sector = au % MDFS_VSB_AU_PER_SECTOR;
    uint32_t byte_off = au_in_sector / 4;
    int bit_pos = (3 - (int)(au_in_sector % 4)) * 2;

    *out_lba = vd->vma_loc + vd->vsb_loc + vsb_sector_idx;
    *out_byte = byte_off;
    *out_shift = bit_pos;

    return MDFS_OK;
}

int mdfs_vsb_get_state(mdfs_io_t *io, const mdfs_vd_t *vd, uint32_t au)
{
    uint32_t lba, byte_off;
    int shift;
    int rc = vsb_locate(vd, au, &lba, &byte_off, &shift);
    if (rc != MDFS_OK)
        return rc;

    uint8_t sector[MDFS_SECTOR_SIZE];
    rc = mdfs_io_read_sector(io, lba, sector);
    if (rc != MDFS_OK)
        return rc;

    return (sector[byte_off] >> shift) & 0x03;
}

int mdfs_vsb_set_state(mdfs_io_t *io, const mdfs_vd_t *vd, uint32_t au, int state)
{
    if (state < 0 || state > 3)
        return MDFS_ERR_INVAL;

    uint32_t lba, byte_off;
    int shift;
    int rc = vsb_locate(vd, au, &lba, &byte_off, &shift);
    if (rc != MDFS_OK)
        return rc;

    uint8_t sector[MDFS_SECTOR_SIZE];
    rc = mdfs_io_read_sector(io, lba, sector);
    if (rc != MDFS_OK)
        return rc;

    /* 2비트 클리어 후 설정 */
    sector[byte_off] &= ~(0x03 << shift);
    sector[byte_off] |= (state & 0x03) << shift;

    return mdfs_io_write_sector(io, lba, sector);
}

int mdfs_vsb_alloc(mdfs_io_t *io, mdfs_vd_t *vd, uint32_t *out_au)
{
    uint8_t sector[MDFS_SECTOR_SIZE];

    for (uint32_t si = 0; si < vd->vsb_num; si++) {
        uint32_t lba = vd->vma_loc + vd->vsb_loc + si;
        if (mdfs_io_read_sector(io, lba, sector) != MDFS_OK)
            continue;

        uint32_t base_au = si * MDFS_VSB_AU_PER_SECTOR;
        for (uint32_t b = 0; b < MDFS_SECTOR_SIZE; b++) {
            if (sector[b] == 0x55) /* all USED */
                continue;
            for (int bit = 3; bit >= 0; bit--) {
                int shift = bit * 2;
                int st = (sector[b] >> shift) & 0x03;
                if (st == MDFS_AU_FREE) {
                    uint32_t au = base_au + b * 4 + (3 - bit);
                    if (au >= vd->num_alloc)
                        return MDFS_ERR_NOSPC;

                    /* USED로 설정 */
                    sector[b] &= ~(0x03 << shift);
                    sector[b] |= (MDFS_AU_USED << shift);
                    int rc = mdfs_io_write_sector(io, lba, sector);
                    if (rc != MDFS_OK)
                        return rc;

                    *out_au = au;
                    vd->num_used++;
                    vd->num_available--;
                    return MDFS_OK;
                }
            }
        }
    }

    return MDFS_ERR_NOSPC;
}

int mdfs_vsb_alloc_contiguous(mdfs_io_t *io, mdfs_vd_t *vd, uint32_t n, uint32_t *out_start)
{
    if (n == 0)
        return MDFS_ERR_INVAL;

    /* 연속 FREE AU 블록 탐색 */
    uint32_t run_start = 0;
    uint32_t run_len = 0;

    for (uint32_t au = 0; au < vd->num_alloc; au++) {
        int st = mdfs_vsb_get_state(io, vd, au);
        if (st == MDFS_AU_FREE) {
            if (run_len == 0)
                run_start = au;
            run_len++;
            if (run_len >= n) {
                /* 전부 USED로 설정 */
                for (uint32_t i = 0; i < n; i++) {
                    int rc = mdfs_vsb_set_state(io, vd, run_start + i, MDFS_AU_USED);
                    if (rc != MDFS_OK)
                        return rc;
                }
                *out_start = run_start;
                vd->num_used += n;
                vd->num_available -= n;
                return MDFS_OK;
            }
        } else {
            run_len = 0;
        }
    }

    return MDFS_ERR_NOSPC;
}

int mdfs_vsb_free(mdfs_io_t *io, mdfs_vd_t *vd, uint32_t au)
{
    int st = mdfs_vsb_get_state(io, vd, au);
    if (st < 0)
        return st;
    if (st != MDFS_AU_USED)
        return MDFS_ERR_INVAL;

    int rc = mdfs_vsb_set_state(io, vd, au, MDFS_AU_FREE);
    if (rc != MDFS_OK)
        return rc;

    vd->num_used--;
    vd->num_available++;
    return MDFS_OK;
}

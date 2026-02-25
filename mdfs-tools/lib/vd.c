/*
 * vd.c — VD (Volume Descriptor) 파싱/생성/검증
 *
 * 온디스크: 빅엔디안, 90 바이트 (0x00-0x59)
 * WS78/79 CONFIRMED: 25 필드 + 4 reserved
 */
#include "mdfs.h"
#include <string.h>
#include <stdio.h>

int mdfs_vd_read(mdfs_io_t *io, uint32_t vd_lba, mdfs_vd_t *vd)
{
    uint8_t sector[MDFS_SECTOR_SIZE];
    int rc = mdfs_io_read_sector(io, vd_lba, sector);
    if (rc != MDFS_OK)
        return rc;

    const mdfs_vd_ondisk_t *raw = (const mdfs_vd_ondisk_t *)sector;

    memset(vd, 0, sizeof(*vd));
    vd->rec_type = raw->rec_type;
    memcpy(vd->ident, raw->ident, 5);
    vd->ident[5] = '\0';
    vd->version = raw->version;

    vd->block_size     = mdfs_be16(raw->block_size);
    vd->cluster_size   = mdfs_be16(raw->cluster_size);
    vd->alloc_size     = mdfs_be16(raw->alloc_size);
    vd->num_alloc      = mdfs_be32(raw->num_alloc);
    vd->num_recordable = mdfs_be32(raw->num_recordable);
    vd->num_available  = mdfs_be32(raw->num_available);
    vd->num_used       = mdfs_be32(raw->num_used);
    vd->num_defective  = mdfs_be32(raw->num_defective);
    vd->num_dir        = mdfs_be16(raw->num_dir);
    vd->num_file       = mdfs_be16(raw->num_file);
    vd->max_id_num     = mdfs_be32(raw->max_id_num);
    vd->vol_attr       = mdfs_be16(raw->vol_attr);
    vd->vma_len        = mdfs_be32(raw->vma_len);
    vd->vma_loc        = mdfs_be32(raw->vma_loc);
    vd->vsb_loc        = mdfs_be16(raw->vsb_loc);
    vd->vsb_num        = mdfs_be16(raw->vsb_num);
    vd->mtb_loc        = mdfs_be16(raw->mtb_loc);
    vd->mtb_num        = mdfs_be16(raw->mtb_num);
    vd->erb_loc        = mdfs_be16(raw->erb_loc);
    vd->erb_num        = mdfs_be16(raw->erb_num);
    vd->drb_loc        = mdfs_be16(raw->drb_loc);
    vd->drb_num        = mdfs_be16(raw->drb_num);
    vd->dir_len        = mdfs_be32(raw->dir_len);
    vd->num_child      = mdfs_be16(raw->num_child);

    /* 런타임 계산 */
    vd->au_bytes = (uint32_t)vd->alloc_size * vd->block_size;

    return MDFS_OK;
}

/* LE→BE 헬퍼 (be16/be32는 자기 역함수) */
static void put_be16(void *dst, uint16_t val)
{
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)(val >> 8);
    p[1] = (uint8_t)(val);
}

static void put_be32(void *dst, uint32_t val)
{
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)(val >> 24);
    p[1] = (uint8_t)(val >> 16);
    p[2] = (uint8_t)(val >> 8);
    p[3] = (uint8_t)(val);
}

int mdfs_vd_write(mdfs_io_t *io, uint32_t vd_lba, const mdfs_vd_t *vd)
{
    uint8_t sector[MDFS_SECTOR_SIZE];

    /* 기존 섹터 읽기 (볼륨 레이블 등 0x5A 이후 보존) */
    int rc = mdfs_io_read_sector(io, vd_lba, sector);
    if (rc != MDFS_OK)
        memset(sector, 0, MDFS_SECTOR_SIZE);

    mdfs_vd_ondisk_t *raw = (mdfs_vd_ondisk_t *)sector;
    raw->rec_type = vd->rec_type;
    memcpy(raw->ident, vd->ident, 5);
    raw->version = vd->version;

    put_be16(&raw->block_size,     vd->block_size);
    put_be16(&raw->cluster_size,   vd->cluster_size);
    put_be16(&raw->alloc_size,     vd->alloc_size);
    put_be32(&raw->num_alloc,      vd->num_alloc);
    put_be32(&raw->num_recordable, vd->num_recordable);
    put_be32(&raw->num_available,  vd->num_available);
    put_be32(&raw->num_used,       vd->num_used);
    put_be32(&raw->num_defective,  vd->num_defective);
    put_be16(&raw->num_dir,        vd->num_dir);
    put_be16(&raw->num_file,       vd->num_file);
    put_be32(&raw->max_id_num,     vd->max_id_num);
    put_be16(&raw->vol_attr,       vd->vol_attr);
    put_be32(&raw->vma_len,        vd->vma_len);
    put_be32(&raw->vma_loc,        vd->vma_loc);
    put_be16(&raw->vsb_loc,        vd->vsb_loc);
    put_be16(&raw->vsb_num,        vd->vsb_num);
    put_be16(&raw->mtb_loc,        vd->mtb_loc);
    put_be16(&raw->mtb_num,        vd->mtb_num);
    put_be16(&raw->erb_loc,        vd->erb_loc);
    put_be16(&raw->erb_num,        vd->erb_num);
    put_be16(&raw->drb_loc,        vd->drb_loc);
    put_be16(&raw->drb_num,        vd->drb_num);
    put_be32(&raw->dir_len,        vd->dir_len);
    put_be16(&raw->num_child,      vd->num_child);

    return mdfs_io_write_sector(io, vd_lba, sector);
}

int mdfs_vd_validate(const mdfs_vd_t *vd)
{
    if (vd->rec_type != 0)
        return MDFS_ERR_INVAL;
    if (memcmp(vd->ident, MDFS_IDENT, MDFS_IDENT_LEN) != 0)
        return MDFS_ERR_INVAL;
    if (vd->block_size == 0 || vd->alloc_size == 0)
        return MDFS_ERR_INVAL;
    if (vd->num_alloc == 0)
        return MDFS_ERR_INVAL;
    if (vd->vma_loc == 0)
        return MDFS_ERR_INVAL;
    if (vd->drb_loc == 0 || vd->drb_num == 0)
        return MDFS_ERR_INVAL;

    /* 카운터 일관성: used + available + defective + reserved ≈ num_alloc */
    uint32_t accounted = vd->num_used + vd->num_available + vd->num_defective;
    if (accounted > vd->num_alloc)
        return MDFS_ERR_CORRUPT;

    return MDFS_OK;
}

uint32_t mdfs_vd_find(mdfs_io_t *io)
{
    /* 테스트 미디어: VD는 항상 LBA 1056 */
    uint8_t sector[MDFS_SECTOR_SIZE];
    if (mdfs_io_read_sector(io, 1056, sector) == MDFS_OK) {
        if (sector[0] == 0 && memcmp(sector + 1, MDFS_IDENT, MDFS_IDENT_LEN) == 0)
            return 1056;
    }
    /* 대안: LBA 0~2000 스캔 */
    for (uint32_t lba = 0; lba < 2048; lba++) {
        if (mdfs_io_read_sector(io, lba, sector) == MDFS_OK) {
            if (sector[0] == 0 && memcmp(sector + 1, MDFS_IDENT, MDFS_IDENT_LEN) == 0)
                return lba;
        }
    }
    return 0; /* 미발견 */
}

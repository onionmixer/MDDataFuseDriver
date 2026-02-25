/*
 * endian.c — 빅엔디안 ↔ 호스트 엔디안 변환
 */
#include "mdfs.h"

uint16_t mdfs_be16(uint16_t v)
{
    const uint8_t *p = (const uint8_t *)&v;
    return (uint16_t)((p[0] << 8) | p[1]);
}

uint32_t mdfs_be32(uint32_t v)
{
    const uint8_t *p = (const uint8_t *)&v;
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

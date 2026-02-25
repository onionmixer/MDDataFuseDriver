/*
 * test_drb.c — DRB 파싱 테스트 (work/mddata_mgmt.bin 기준)
 *
 * 테스트 미디어 기대값 (WS82+85 CONFIRMED):
 *   Root: CSC=2(dir), name="", attr=0x0301, DLoc=5, CNum=1, DataSize=2048
 *   Z920.EXE: CSC=1(file), attr=0x0040, FLoc=392, FNum=136, DataSize=1110476
 */
#include "mdfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define TEST_IMAGE "../resource/work_scripts/mddata_mgmt.bin"

static int tests_passed = 0;
static int tests_failed = 0;

#define CHECK(cond, msg) do { \
    if (cond) { tests_passed++; } \
    else { tests_failed++; fprintf(stderr, "FAIL: %s\n", msg); } \
} while(0)

int main(void)
{
    printf("test_drb: DRB 파싱 검증 (%s)\n", TEST_IMAGE);

    mdfs_io_t *io = mdfs_io_open(TEST_IMAGE, 1);
    if (!io) {
        fprintf(stderr, "오류: %s 열기 실패\n", TEST_IMAGE);
        return 1;
    }

    /* VD 읽기 */
    mdfs_vd_t vd;
    int rc = mdfs_vd_read(io, 1056, &vd);
    CHECK(rc == MDFS_OK, "VD read success");

    /* DRB 읽기 */
    mdfs_entry_t entries[64];
    int count = 0;
    uint32_t drb_lba = vd.vma_loc + vd.drb_loc;
    rc = mdfs_drb_read(io, &vd, drb_lba, vd.drb_num, entries, &count, 64);
    CHECK(rc == MDFS_OK, "DRB read success");
    CHECK(count == 2, "DRB entry count == 2");

    if (count >= 2) {
        /* Root 엔트리 */
        mdfs_entry_t *root = &entries[0];
        CHECK(root->csc == MDFS_CSC_DIR, "Root CSC == DIR");
        CHECK(root->attr == 0x0301, "Root attr == 0x0301 (ADIR|AINHDELETE|AINHRENAME)");
        CHECK(root->data_size == 2048, "Root DataSize == 2048");
        CHECK(root->dloc == 5, "Root DLoc == 5");
        CHECK(root->cnum == 1, "Root CNum == 1");
        CHECK(root->entry_id == 2, "Root EntryID == 2");

        /* Z920.EXE 엔트리 */
        mdfs_entry_t *z920 = &entries[1];
        CHECK(z920->csc == MDFS_CSC_FILE, "Z920 CSC == FILE");
        CHECK(z920->attr == 0x0040, "Z920 attr == 0x0040 (APROTECT)");
        CHECK(strcmp(z920->name, "Z920.EXE") == 0, "Z920 name == 'Z920.EXE'");
        CHECK(z920->data_size == 1110476, "Z920 DataSize == 1110476");
        CHECK(z920->floc == 392, "Z920 FLoc == 392");
        CHECK(z920->fnum == 136, "Z920 FNum == 136");
        CHECK(z920->alen == 0, "Z920 ALen == 0");
        CHECK(z920->aloc == 0, "Z920 ALoc == 0");
        CHECK(z920->anum == 0, "Z920 ANum == 0");
        CHECK(z920->entry_id == 16, "Z920 EntryID == 16 (== MaxIdNum)");

        /* AU→LBA 변환 검증 */
        uint32_t z920_lba = mdfs_au_to_lba(&vd, z920->floc);
        CHECK(z920_lba == 1568, "Z920 LBA == 1568 (392*4)");

        /* ceil(1110476/8192) == 136 AU 확인 */
        uint32_t expected_au = (1110476 + 8191) / 8192;
        CHECK(expected_au == 136, "ceil(DataSize/AU) == 136 == FNum");

        /* 이름 변환 테스트 */
        char decoded[13];
        mdfs_name_decode(z920->raw_name, decoded);
        CHECK(strcmp(decoded, "Z920.EXE") == 0, "name_decode(Z920)");

        char encoded[10];
        CHECK(mdfs_name_encode("Z920.EXE", encoded) == MDFS_OK, "name_encode success");
        CHECK(memcmp(encoded, z920->raw_name, 10) == 0, "name_encode round-trip");

        /* 파일 데이터 읽기 테스트 — MZ 헤더 확인 */
        uint8_t mz_buf[2];
        size_t bytes_read = 0;
        rc = mdfs_data_read(io, &vd, z920, 0, mz_buf, 2, &bytes_read);
        CHECK(rc == MDFS_OK, "data_read success");
        CHECK(bytes_read == 2, "data_read 2 bytes");
        CHECK(mz_buf[0] == 'M' && mz_buf[1] == 'Z', "Z920.EXE starts with MZ header");
    }

    mdfs_io_close(io);

    printf("\ntest_drb: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}

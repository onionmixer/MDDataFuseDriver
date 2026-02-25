CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11 -D_FILE_OFFSET_BITS=64 -g -O2
FUSE_CFLAGS = $(shell pkg-config --cflags fuse3)
FUSE_LIBS = $(shell pkg-config --libs fuse3)

INCDIR = include
LIB_SRCS = lib/endian.c lib/io.c lib/vd.c lib/vsb.c lib/mtb.c lib/drb.c lib/extent.c
LIB_OBJS = $(LIB_SRCS:.c=.o)

.PHONY: all clean test

all: mdfs-fuse mdfsformat

# 정적 라이브러리
libmdfs.a: $(LIB_OBJS)
	ar rcs $@ $^

# FUSE 드라이버
fuse/mdfs_fuse.o: fuse/mdfs_fuse.c $(INCDIR)/mdfs.h
	$(CC) $(CFLAGS) $(FUSE_CFLAGS) -I$(INCDIR) -c $< -o $@

mdfs-fuse: fuse/mdfs_fuse.o libmdfs.a
	$(CC) -o $@ $< -L. -lmdfs $(FUSE_LIBS)

# 포맷 도구 (Phase 3)
format/mdfsformat.o: format/mdfsformat.c $(INCDIR)/mdfs.h
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

mdfsformat: format/mdfsformat.o libmdfs.a
	$(CC) -o $@ $< -L. -lmdfs

# 라이브러리 오브젝트
lib/%.o: lib/%.c $(INCDIR)/mdfs.h
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

# 테스트
test/test_vd.o: test/test_vd.c $(INCDIR)/mdfs.h
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

test/test_drb.o: test/test_drb.c $(INCDIR)/mdfs.h
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

test_vd: test/test_vd.o libmdfs.a
	$(CC) -o $@ $< -L. -lmdfs

test_drb: test/test_drb.o libmdfs.a
	$(CC) -o $@ $< -L. -lmdfs

test: test_vd test_drb
	@echo "=== VD 파싱 테스트 ==="
	./test_vd
	@echo ""
	@echo "=== DRB 파싱 테스트 ==="
	./test_drb
	@echo ""
	@echo "=== 전체 테스트 통과 ==="

clean:
	rm -f lib/*.o fuse/*.o format/*.o test/*.o
	rm -f libmdfs.a mdfs-fuse mdfsformat test_vd test_drb

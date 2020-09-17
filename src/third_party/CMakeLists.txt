cmake_minimum_required(VERSION 3.6)
project(third_party)

set(SNAPPY_SRC
  	snappy/snappy-internal.h
	snappy/snappy-sinksource.cc
	snappy/snappy-sinksource.h
	snappy/snappy-stubs-internal.cc
	snappy/snappy-stubs-internal.h
	snappy/snappy-stubs-public.h
	snappy/snappy-c.cc
	snappy/snappy.cc
	snappy/snappy.h
)

set(LZ4_SRC
	lz4/lz4.c
	lz4/lz4.h
	lz4/lz4hc.h
	lz4/lz4hc.c
	lz4/lz4frame.h
	lz4/lz4frame.c
	lz4/xxhash.c
	lz4/xxhash.h
)

set(ZSTD_SRC
	zstd/compress/zstd_compress.c
	zstd/common/zstd_common.c
	zstd/decompress/zstd_decompress.c
	zstd/decompress/zstd_decompress_block.c
	zstd/decompress/zstd_ddict.c
	zstd/decompress/huf_decompress.c
	zstd/compress/zstd_ldm.c
	zstd/compress/zstd_double_fast.c
	zstd/compress/zstd_fast.c
	zstd/compress/zstd_opt.c
	zstd/compress/huf_compress.c
	zstd/compress/hist.c
	zstd/compress/fse_compress.c
	zstd/compress/zstd_lazy.c
	zstd/compress/zstd_compress_superblock.c
	zstd/common/fse_decompress.c
	zstd/common/entropy_common.c
	zstd/common/error_private.c
	zstd/compress/zstd_compress_literals.c
	zstd/compress/zstd_compress_sequences.c
)

add_library(
	${PROJECT_NAME} OBJECT
	${SNAPPY_SRC}
	${LZ4_SRC}
	${ZSTD_SRC}
)

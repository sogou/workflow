/*
  Copyright (c) 2020 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

	  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Authors: Wang Zhulei (wangzhulei@sogou-inc.com)
*/

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sstream>
#include <utility>
#include <algorithm>
#include <set>
#include <string.h>
#include <zlib.h>
#include <lz4.h>
#include <lz4frame.h>
#include <zstd_errors.h>
#include <zstd.h>
#include <snappy-c.h>
#include <snappy.h>
#include <snappy-sinksource.h>
#include "crc32c.h"
#include "KafkaMessage.h"

namespace protocol
{

#define CHECK_RET(exp) \
do { \
	int tmp = exp; \
	if (tmp < 0) \
		return tmp; \
} while (0)

#ifndef htonll
static uint64_t htonll(uint64_t x)
{
	if (1 == htonl(1))
		return x;
	else
		return ((uint64_t)htonl(x & 0xFFFFFFFF) << 32) + htonl(x >> 32);
}
#endif

static size_t append_bool(std::string& buf, bool val)
{
	unsigned char v = 0;

	if (val)
		v = 1;

	buf.append((char *)&v, 1);
	return 1;
}

static size_t append_i8(std::string& buf, int8_t val)
{
	buf.append((char *)&val, 1);
	return 1;
}

static size_t append_i8(void **buf, int8_t val)
{
	*(char *)*buf  = val;
	*buf = (char *)*buf + 1;
	return 1;
}

static size_t append_i16(std::string& buf, int16_t val)
{
	int16_t v = htons(val);

	buf.append((char *)&v, 2);
	return 2;
}

static size_t append_i32(std::string& buf, int32_t val)
{
	int32_t v = htonl(val);

	buf.append((char *)&v, 4);
	return 4;
}

static size_t append_i32(void **buf, int32_t val)
{
	int32_t v = htonl(val);

	*(int32_t *)*buf = v;
	*buf = (int32_t *)*buf + 1;
	return 4;
}

static size_t append_i64(std::string& buf, int64_t val)
{
	int64_t v = htonll(val);

	buf.append((char *)&v, 8);
	return 8;
}

static size_t append_i64(void **buf, int64_t val)
{
	int64_t v = htonll(val);

	*(int64_t *)*buf = v;
	*buf = (int64_t *)*buf + 1;
	return 8;
}

static size_t append_string(std::string& buf, const char *str, size_t len)
{
	append_i16(buf, len);
	buf.append(str, len);
	return len + 2;
}

static size_t append_string(std::string& buf, const char *str)
{
	if (!str)
		return append_string(buf, "", 0);

	return append_string(buf, str, strlen(str));
}

static size_t append_string_raw(std::string& buf, const char *str, size_t len)
{
	buf.append(str, len);
	return len;
}

static size_t append_nullable_string(std::string& buf, const char *str, size_t len)
{
	if (len == 0)
		return append_i16(buf, -1);
	else
		return append_string(buf, str, len);
}

static size_t append_string_raw(void **buf, const char *str, size_t len)
{
	memcpy(*buf, str, len);
	*buf = (char *)*buf + len;
	return len;
}

static size_t append_string_raw(void **buf, const std::string& str)
{
	return append_string_raw(buf, str.c_str(), str.size());
}

static size_t append_bytes(std::string& buf, const char *str, size_t len)
{
	append_i32(buf, len);
	buf.append(str, len);
	return 4 + len;
}

static size_t append_bytes(std::string& buf, const std::string& str)
{
	return append_bytes(buf, str.c_str(), str.size());
}

static size_t append_bytes(void **buf, const char *str, size_t len)
{
	*((int32_t *)*buf) = htonl(len);
	*buf = (int32_t *)*buf + 1;

	memcpy(*buf, str, len);
	*buf = (char *)*buf + len;

	return len + 2;
}

static size_t append_nullable_bytes(void **buf, const char *str, size_t len)
{
	if (len == 0)
		return append_i32(buf, -1);
	else
		return append_bytes(buf, str, len);
}

static size_t append_varint_u64(std::string& buf, uint64_t num)
{
	size_t len = 0;

	do
	{
		unsigned char v = (num & 0x7f) | (num > 0x7f ? 0x80 : 0);
		buf.append((char *)&v, 1);
		num >>= 7;
		++len;
	} while (num);
	return len;
}

static inline size_t append_varint_i64(std::string& buf, int64_t num)
{
	return append_varint_u64(buf, (num << 1) ^ (num >> 63));
}

static inline size_t append_varint_i32(std::string& buf, int32_t num)
{
	return append_varint_i64(buf, num);
}

static size_t append_compact_string(std::string& buf, const char *str)
{
	if (!str || str[0] == '\0')
		append_string(buf, "");

	size_t len = strlen(str);
	size_t r = append_varint_u64(buf, len + 1);
	append_string_raw(buf, str, len);
	return r + len;
}

static inline int parse_i8(void **buf, size_t *size, int8_t *val)
{
	if (*size >= 1)
	{
		*val = *(int8_t *)*buf;
		*size -= sizeof(int8_t);
		*buf = (int8_t *)*buf + 1;
		return 0;
	}

	errno = EBADMSG;
	return -1;
}

static inline int parse_i16(void **buf, size_t *size, int16_t *val)
{
	if (*size >= 2)
	{
		*val = ntohs(*(int16_t *)*buf);
		*size -= sizeof(int16_t);
		*buf = (int16_t *)*buf + 1;
		return 0;
	}

	errno = EBADMSG;
	return -1;
}

static inline int parse_i32(void **buf, size_t *size, int32_t *val)
{
	if (*size >= 4)
	{
		*val = ntohl(*(int32_t *)*buf);
		*size -= sizeof(int32_t);
		*buf = (int32_t *)*buf + 1;
		return 0;
	}

	errno = EBADMSG;
	return -1;
}

static inline int parse_i64(void **buf, size_t *size, int64_t *val)
{
	if (*size >= 8)
	{
		*val = htonll(*(int64_t *)*buf);
		*size -= sizeof(int64_t);
		*buf = (int64_t *)*buf + 1;
		return 0;
	}

	errno = EBADMSG;
	return -1;
}

static int parse_string(void **buf, size_t *size, std::string& str);

static int parse_string(void **buf, size_t *size, char **str);

static int parse_bytes(void **buf, size_t *size, std::string& str);

static int parse_bytes(void **buf, size_t *size,
					   void **str, size_t *str_len);

static int parse_varint_u64(void **buf, size_t *size, uint64_t *val);

static int parse_varint_i64(void **buf, size_t *size, int64_t *val)
{
	uint64_t n;
	int ret = parse_varint_u64(buf, size, &n);

	if (ret == 0)
		*val = (int64_t)(n >> 1) ^ -(int64_t)(n & 1);

	return ret;
}

static int parse_varint_i32(void **buf, size_t *size, int32_t *val)
{
	int64_t v = 0;

	if (parse_varint_i64(buf, size, &v) < 0)
		return -1;

	*val = (int32_t)v;
	return 0;
}

static const LZ4F_preferences_t kPrefs =
{
	.frameInfo = {LZ4F_default, LZ4F_blockIndependent, },
	.compressionLevel = 0,
};

static int compress_buf(KafkaBlock *block, int compress_type, void *env)
{
	z_stream *c_stream;
	size_t total_in = 0, gzip_in, bound_size;
	KafkaBuffer *snappy_buffer;
	KafkaBlock nblock;
	LZ4F_errorCode_t lz4_r;
	LZ4F_cctx *lz4_cctx;
	ZSTD_CStream *zstd_cctx;
	size_t zstd_r;
	ZSTD_outBuffer out;
	ZSTD_inBuffer in;

	switch (compress_type)
	{
	case Kafka_Gzip:
		c_stream = static_cast<z_stream *>(env);
		gzip_in = c_stream->total_in;
		while (total_in < block->get_len())
		{
			if (c_stream->avail_in == 0)
			{
				c_stream->next_in = (Bytef *)block->get_block();
				c_stream->avail_in = block->get_len() - total_in;
			}

			if (c_stream->avail_out == 0)
			{
				bound_size = compressBound(c_stream->avail_in);
				if (!nblock.allocate(bound_size))
				{
					delete c_stream;
					return -1;
				}

				c_stream->next_out = (Bytef *)nblock.get_block();
				c_stream->avail_out = bound_size;
			}

			if (deflate(c_stream, Z_NO_FLUSH) != Z_OK)
			{
				delete c_stream;
				errno = EBADMSG;
				return -1;
			}

			total_in += c_stream->total_in - gzip_in;
			gzip_in = c_stream->total_in;
		}

		*block = std::move(nblock);

		break;

	case Kafka_Snappy:
		snappy_buffer = static_cast<KafkaBuffer *>(env);
		snappy_buffer->append((const char *)block->get_block(), block->get_len());

		break;

	case Kafka_Lz4:
		lz4_cctx = static_cast<LZ4F_cctx *>(env);
		bound_size = LZ4F_compressBound(block->get_len(), &kPrefs);
		if (!nblock.allocate(bound_size))
		{
			LZ4F_freeCompressionContext(lz4_cctx);
			return -1;
		}

		lz4_r = LZ4F_compressUpdate(lz4_cctx,
									nblock.get_block(), nblock.get_len(),
									block->get_block(), block->get_len(),
									NULL);

		if (LZ4F_isError(lz4_r))
		{
			LZ4F_freeCompressionContext(lz4_cctx);
			errno = EBADMSG;
			return -1;
		}

		nblock.set_len(lz4_r);
		*block = std::move(nblock);
		break;

	case Kafka_Zstd:
		zstd_cctx = static_cast<ZSTD_CStream *>(env);
		bound_size = ZSTD_compressBound(block->get_len());
		if (!nblock.allocate(bound_size))
		{
			ZSTD_freeCStream(zstd_cctx);
			return -1;
		}

		in.src = block->get_block();
		in.pos = 0;
		in.size = block->get_len();
		out.dst = nblock.get_block();
		out.pos = 0;
		out.size = nblock.get_len();
		zstd_r = ZSTD_compressStream(zstd_cctx, &out, &in);
		if (ZSTD_isError(zstd_r) || in.pos < in.size)
		{
			ZSTD_freeCStream(zstd_cctx);
			errno = EBADMSG;
			return -1;
		}

		nblock.set_len(out.pos);
		*block = std::move(nblock);
		break;

	default:
		return 0;
	}

	return 0;
}

static int gzip_decompress(void *compressed, size_t n, KafkaBlock *block)
{
	for (int pass = 1; pass <= 2; pass++)
	{
		z_stream strm = {0};
		gz_header hdr;
		char buf[512];
		char *p;
		int len;
		int r;

		if ((r = inflateInit2(&strm, 15 | 32)) != Z_OK)
		{
			errno = EBADMSG;
			return -1;
		}

		strm.next_in = (Bytef *)compressed;
		strm.avail_in = n;

		if ((r = inflateGetHeader(&strm, &hdr)) != Z_OK)
		{
			inflateEnd(&strm);
			errno = EBADMSG;
			return -1;
		}

		if (pass == 1)
		{
			p = buf;
			len = sizeof(buf);
		}
		else
		{
			p = (char *)block->get_block();
			len = block->get_len();
		}

		do
		{
			strm.next_out = (unsigned char *)p;
			strm.avail_out = len;

			r = inflate(&strm, Z_NO_FLUSH);
			switch (r)
			{
			case Z_STREAM_ERROR:
			case Z_NEED_DICT:
			case Z_DATA_ERROR:
			case Z_MEM_ERROR:
				inflateEnd(&strm);
				errno = EBADMSG;
				return -1;
			}

			if (pass == 2)
			{
				p += len - strm.avail_out;
				len -= len - strm.avail_out;
			}

		} while (strm.avail_out == 0 && r != Z_STREAM_END);


		if (pass == 1)
		{
			if (!block->allocate(strm.total_out))
			{
				inflateEnd(&strm);
				return -1;
			}
		}

		inflateEnd(&strm);

		if (strm.total_in != n || r != Z_STREAM_END)
		{
			errno = EBADMSG;
			return -1;
		}
	}

	return 0;
}

static int kafka_snappy_java_uncompress(const char *inbuf, size_t inlen, KafkaBlock *block)
{
	char *obuf = NULL;

	for (int pass = 1; pass <= 2; pass++)
	{
		ssize_t off = 0;
		ssize_t uoff = 0;

		while (off + 4 <= (ssize_t)inlen)
		{
			uint32_t clen;
			size_t ulen;

			memcpy(&clen, inbuf + off, 4);
			clen = ntohl(clen);
			off += 4;

			if (clen > inlen - off)
			{
				errno = EBADMSG;
				return -1;
			}

			if (snappy_uncompressed_length(inbuf + off, clen, &ulen) != SNAPPY_OK)
			{
				errno = EBADMSG;
				return -1;
			}

			if (pass == 1)
			{
				off += clen;
				uoff += ulen;
				continue;
			}

			size_t n = block->get_len() - uoff;

			if (snappy_uncompress(inbuf + off, clen, obuf + uoff, &n) != SNAPPY_OK)
			{
				errno = EBADMSG;
				return -1;
			}

			off += clen;
			uoff += ulen;
		}

		if (off != (ssize_t)inlen)
		{
			errno = EBADMSG;
			return -1;
		}

		if (pass == 1)
		{
			if (uoff <= 0)
			{
				errno = EBADMSG;
				return -1;
			}

			if (!block->allocate(uoff))
				return -1;

			obuf = (char *)block->get_block();
		}
		else
			block->set_len(uoff);
	}

	return 0;
}

static int snappy_decompress(void *buf, size_t n, KafkaBlock *block)
{
	const char *inbuf = (const char *)buf;
	size_t inlen = n;
	static const unsigned char snappy_java_magic[] = {
		0x82, 'S','N','A','P','P','Y', 0
	};
	static const size_t snappy_java_hdrlen = 8 + 4 + 4;

	if (!memcmp(buf, snappy_java_magic, 8))
	{
		inbuf = inbuf + snappy_java_hdrlen;
		inlen -= snappy_java_hdrlen;
		return kafka_snappy_java_uncompress(inbuf, inlen, block);
	}
	else
	{
		size_t uncompressed_len;

		if (snappy_uncompressed_length(inbuf, n, &uncompressed_len) != SNAPPY_OK)
		{
			errno = EBADMSG;
			return -1;
		}

		if (!block->allocate(uncompressed_len))
			return -1;

		size_t nn = block->get_len();

		return snappy_uncompress(inbuf, n, (char *)block->get_block(), &nn);
	}
}

static int lz4_decompress(void *buf, size_t n, KafkaBlock *block)
{
	LZ4F_errorCode_t code;
	LZ4F_decompressionContext_t dctx;
	LZ4F_frameInfo_t fi;
	size_t in_sz, out_sz;
	size_t in_off, out_off;
	size_t r;
	size_t uncompressed_size;
	size_t outlen;
	char *out = NULL;
	size_t inlen = n;

	const char *inbuf = (const char *)buf;

	code = LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);
	if (LZ4F_isError(code))
	{
		code = LZ4F_freeDecompressionContext(dctx);
		errno = EBADMSG;
		return -1;
	}

	in_sz = n;
	r = LZ4F_getFrameInfo(dctx, &fi, (const void *)buf, &in_sz);
	if (LZ4F_isError(r))
	{
		code = LZ4F_freeDecompressionContext(dctx);
		errno = EBADMSG;
		return -1;
	}

	if (fi.contentSize == 0 || fi.contentSize > inlen * 255)
		uncompressed_size = inlen * 4;
	else
		uncompressed_size = (size_t)fi.contentSize;

	if (!block->allocate(uncompressed_size))
	{
		code = LZ4F_freeDecompressionContext(dctx);
		return -1;
	}

	out = (char *)block->get_block();
	outlen = block->get_len();
	in_off = in_sz;
	out_off = 0;
	while (in_off < inlen)
	{
		out_sz = outlen - out_off;
		in_sz = inlen - in_off;
		r = LZ4F_decompress(dctx, out + out_off, &out_sz,
							inbuf + in_off, &in_sz, NULL);
		if (LZ4F_isError(r))
		{
			code = LZ4F_freeDecompressionContext(dctx);
			errno = EBADMSG;
			return -1;
		}

		if (!(out_off + out_sz <= outlen && in_off + in_sz <= inlen))
		{
			code = LZ4F_freeDecompressionContext(dctx);
			errno = EBADMSG;
			return -1;
		}

		out_off += out_sz;
		in_off += in_sz;
		if (r == 0)
			break;

		if (out_off == outlen)
		{
			size_t extra = outlen * 3 / 4;

			if (!block->reallocate(outlen + extra))
			{
				code = LZ4F_freeDecompressionContext(dctx);
				errno = EBADMSG;
				return -1;
			}

			out = (char *)block->get_block();
			outlen += extra;
		}
	}


	if (in_off < inlen)
	{
		code = LZ4F_freeDecompressionContext(dctx);
		errno = EBADMSG;
		return -1;
	}

	LZ4F_freeDecompressionContext(dctx);
	return 0;
}

static int zstd_decompress(void *buf, size_t n, KafkaBlock *block)
{
	unsigned long long out_bufsize = ZSTD_getFrameContentSize(buf, n);

	switch (out_bufsize)
	{
	case ZSTD_CONTENTSIZE_UNKNOWN:
		out_bufsize = n * 2;
		break;

	case ZSTD_CONTENTSIZE_ERROR:
		errno = EBADMSG;
		return -1;

	default:
		break;
	}

	while (1)
	{
		size_t ret;

		if (!block->allocate(out_bufsize))
			return -1;

		ret = ZSTD_decompress(block->get_block(), out_bufsize,
							  buf, n);

		if (!ZSTD_isError(ret))
			return 0;

		if (ZSTD_getErrorCode(ret) == ZSTD_error_dstSize_tooSmall)
		{
			out_bufsize += out_bufsize * 2;
		}
		else
		{
			errno = EBADMSG;
			return -1;
		}
	}
}

static int uncompress_buf(void *buf, size_t size, KafkaBlock *block,
						  int compress_type)
{
	switch(compress_type)
	{
	case Kafka_Gzip:
		return gzip_decompress(buf, size, block);

	case Kafka_Snappy:
		return snappy_decompress(buf, size, block);

	case Kafka_Lz4:
		return lz4_decompress(buf, size, block);

	case Kafka_Zstd:
		return zstd_decompress(buf, size, block);

	default:
		errno = EBADMSG;
		return -1;
	}
}

static int append_message_set(KafkaBlock *block,
							  const KafkaRecord *record,
							  int offset, int msg_version,
							  const KafkaConfig& config, void *env,
							  int cur_msg_size)
{
	const void *key;
	size_t key_len;
	record->get_key(&key, &key_len);

	const void *value;
	size_t value_len;
	record->get_value(&value, &value_len);

	int message_size = 4 + 1 + 1 + 4 + 4 + key_len + value_len;

	if (msg_version == 1)
		message_size += 8;

	int max_msg_size = std::min(config.get_produce_msgset_max_bytes(),
								config.get_produce_msg_max_bytes());
	if (message_size + 8 + 4 + cur_msg_size > max_msg_size)
		return 1;

	if (!block->allocate(message_size + 8 + 4))
		return -1;

	void *cur = block->get_block();

	append_i64(&cur, offset);
	append_i32(&cur, message_size);

	int crc_32 = crc32(0, NULL, 0);

	append_i32(&cur, crc_32); //need update
	append_i8(&cur, msg_version);
	append_i8(&cur, 0);

	if (msg_version == 1)
		append_i64(&cur, record->get_timestamp());

	append_bytes(&cur, (const char *)key, key_len);
	append_nullable_bytes(&cur, (const char *)value, value_len);

	char *crc_buf = (char *)block->get_block() + 8 + 4;

	crc_32 = crc32(crc_32, (Bytef *)(crc_buf + 4), message_size - 4);
	*(uint32_t *)crc_buf = htonl(crc_32);

	if (compress_buf(block, config.get_compress_type(), env) < 0)
		return -1;

	return 0;
}

static int append_batch_record(KafkaBlock *block,
							   const KafkaRecord *record,
							   int offset, const KafkaConfig& config,
							   int64_t first_timestamp, void *env,
							   int cur_msg_size)
{
	const void *key;
	size_t key_len;
	record->get_key(&key, &key_len);

	const void *value;
	size_t value_len;
	record->get_value(&value, &value_len);

	std::string klen_str;
	std::string vlen_str;
	std::string timestamp_delta_str;
	int64_t timestamp_delta = record->get_timestamp() - first_timestamp;

	append_varint_i64(timestamp_delta_str, timestamp_delta);

	std::string offset_delta_str;
	append_varint_i64(offset_delta_str, offset);

	if (key_len > 0)
		append_varint_i32(klen_str, (int32_t)key_len);
	else
		append_varint_i32(klen_str, (int32_t)-1);

	if (value)
		append_varint_i32(vlen_str, (int32_t)value_len);
	else
		append_varint_i32(vlen_str, -1);

	struct list_head *pos;
	kafka_record_header_t *header;
	std::string hdr_str;
	int hdr_cnt = 0;

	list_for_each(pos, record->get_header_list())
	{
		header = list_entry(pos, kafka_record_header_t, list);
		append_varint_i32(hdr_str, (int32_t)header->key_len);
		append_string_raw(hdr_str, (const char *)header->key, header->key_len);
		append_varint_i32(hdr_str, (int32_t)header->value_len);
		append_string_raw(hdr_str, (const char *)header->value, header->value_len);
		++hdr_cnt;
	}

	std::string hdr_cnt_str;
	append_varint_i32(hdr_cnt_str, hdr_cnt);

	int length = 1 + timestamp_delta_str.size() + offset_delta_str.size() +
		klen_str.size() + key_len + vlen_str.size() + value_len +
		hdr_cnt_str.size() + hdr_str.size();

	std::string length_str;
	append_varint_i32(length_str, length);

	int max_msg_size = std::min(config.get_produce_msgset_max_bytes(),
								config.get_produce_msg_max_bytes());
	if ((int)(length + length_str.size() + cur_msg_size) > max_msg_size)
		return 1;

	if (!block->allocate(length + length_str.size()))
		return false;

	void *cur = block->get_block();

	append_string_raw(&cur, length_str);
	append_i8(&cur, 0);
	append_string_raw(&cur, timestamp_delta_str);
	append_string_raw(&cur, offset_delta_str);
	append_string_raw(&cur, klen_str);

	if (key_len > 0)
		append_string_raw(&cur, (const char *)key, key_len);

	append_string_raw(&cur, vlen_str);
	if (value_len > 0)
		append_string_raw(&cur, (const char *)value, value_len);

	append_string_raw(&cur, hdr_cnt_str);
	if (hdr_cnt > 0)
		append_string_raw(&cur, hdr_str);

	if (compress_buf(block, config.get_compress_type(), env) < 0)
		return -1;

	return 0;
}

static int append_record(KafkaBlock *block,
						 const KafkaRecord *record,
						 int offset, int msg_version,
						 const KafkaConfig& config,
						 int64_t first_timestamp, void *env,
						 int cur_msg_size)
{
	if (config.get_produce_msgset_cnt() < offset)
		return 1;

	int ret = 0;

	switch (msg_version)
	{
	case 0:
	case 1:
		ret = append_message_set(block, record, offset, msg_version,
								 config, env, cur_msg_size);
		break;

	case 2:
		ret = append_batch_record(block, record, offset, config,
								  first_timestamp, env, cur_msg_size);
		break;

	default:
		break;
	}

	return ret;
}

static int parse_string(void **buf, size_t *size, std::string& str)
{
	if (*size >= 2)
	{
		int16_t len;

		if (parse_i16(buf, size, &len) >= 0)
		{
			if (len >= -1)
			{
				if (len == -1)
					len = 0;

				if (*size >= (size_t)len)
				{
					str.assign((char *)*buf, len);
					*size -= len;
					*buf = (char *)*buf + len;
					return 0;
				}
				else
				{
					*buf = (char *)*buf - 2;
					*size += 2;
				}
			}
		}
	}

	errno = EBADMSG;
	return -1;
}

static int parse_string(void **buf, size_t *size, char **str)
{
	if (*size >= 2)
	{
		int16_t len;

		if (parse_i16(buf, size, &len) >= 0)
		{
			if (len >= -1)
			{
				if (len == -1)
					len = 0;

				if (*size >= (size_t)len)
				{
					char *p = (char *)malloc(len + 1);

					if (!p)
					{
						*buf = (char *)*buf - 2;
						*size += 2;
						return -1;
					}

					free(*str);
					memcpy((void *)p, *buf, len);
					p[len] = 0;
					*size -= len;
					*buf = (char *)*buf + len;
					*str = p;

					return 0;
				}
				else
				{
					*buf = (char *)*buf - 2;
					*size += 2;
				}
			}
		}
	}

	errno = EBADMSG;
	return -1;
}

static int parse_bytes(void **buf, size_t *size, std::string& str)
{
	if (*size >= 4)
	{
		int32_t len;

		if (parse_i32(buf, size, &len) >= 0)
		{
			if (len == -1)
				len = 0;

			if (*size >= (size_t)len)
			{
				str.assign((char *)*buf, len);
				*size -= len;
				*buf = (char *)*buf + len;

				return 0;
			}
			else
			{
				*buf = (char *)*buf - 4;
				*size += 4;
			}
		}
	}

	errno = EBADMSG;
	return -1;
}

static int parse_bytes(void **buf, size_t *size,
					   void **str, size_t *str_len)
{
	if (*size >= 4)
	{
		int32_t len;

		if (parse_i32(buf, size, &len) >= 0)
		{
			if (len == -1)
				len = 0;

			if (*size >= (size_t)len)
			{
				*str = *buf;
				*str_len = len;
				*size -= len;
				*buf = (char *)*buf + len;

				return 0;
			}
			else
			{
				*buf = (char *)*buf - 4;
				*size += 4;
			}
		}
	}

	errno = EBADMSG;
	return -1;
}

static int parse_varint_u64(void **buf, size_t *size, uint64_t *val)
{
	size_t off = 0;
	uint64_t num = 0;
	int shift = 0;
	size_t org_size = *size;

	do
	{
		if (*size == 0)
		{
			*size = org_size;
			errno = EBADMSG;
			return -1; /* Underflow */
		}

		num |= (uint64_t)(((char *)(*buf))[(int)off] & 0x7f) << shift;
		shift += 7;
	} while (((char *)(*buf))[(int)off++] & 0x80);

	*val = num;
	*buf = (char *)(*buf) + off;
	*size -= off;
	return 0;
}

int KafkaMessage::parse_message_set(void **buf, size_t *size,
									bool check_crcs, int msg_vers,
									struct list_head *record_list,
									KafkaBuffer *uncompressed,
									KafkaToppar *toppar)
{
	int64_t offset;
	int32_t message_size;
	int32_t crc;

	if (parse_i64(buf, size, &offset) < 0)
		return -1;

	if (parse_i32(buf, size, &message_size) < 0)
		return -1;

	if (*size < (size_t)(message_size - 8))
		return 1;

	if (parse_i32(buf, size, &crc) < 0)
		return -1;

	if (check_crcs)
	{
		int32_t crc_32 = crc32(0, NULL, 0);
		crc_32 = crc32(crc_32, (Bytef *)*buf, message_size - 4);
		if (crc_32 != crc)
		{
			errno = EBADMSG;
			return -1;
		}
	}

	int8_t magic;
	int8_t attributes;

	if (parse_i8(buf, size, &magic) < 0)
		return -1;

	if (parse_i8(buf, size, &attributes) < 0)
		return -1;

	int64_t timestamp = -1;
	if (msg_vers == 1 && parse_i64(buf, size, &timestamp) < 0)
		return -1;

	void *key;
	size_t key_len;
	if (parse_bytes(buf, size, &key, &key_len) < 0)
		return -1;

	void *payload;
	size_t payload_len;

	if (parse_bytes(buf, size, &payload, &payload_len) < 0)
		return -1;

	if (offset >= toppar->get_offset())
	{
		int compress_type = attributes & 3;
		if (compress_type == 0)
		{
			KafkaRecord *kafka_record = new KafkaRecord;
			kafka_record_t *record = kafka_record->get_raw_ptr();
			record->key = key;
			record->key_len = key_len;
			record->timestamp = timestamp;
			record->offset = offset;
			record->toppar = toppar->get_raw_ptr();
			record->key_is_moved = 1;
			record->value_is_moved = 1;
			record->value = payload;
			record->value_len = payload_len;
			list_add_tail(kafka_record->get_list(), record_list);
		}
		else
		{
			KafkaBlock block;
			if (uncompress_buf(payload, payload_len, &block, compress_type) < 0)
				return -1;

			struct list_head *record_head = record_list->prev;
			void *uncompressed_ptr = block.get_block();
			size_t uncompressed_len = block.get_len();
			parse_message_set(&uncompressed_ptr, &uncompressed_len, check_crcs,
							msg_vers, record_list, uncompressed, toppar);

			uncompressed->add_item(std::move(block));

			if (msg_vers == 1)
			{
				struct list_head *pos;
				KafkaRecord *record;
				int n = 0;

				for (pos = record_head->next; pos != record_list; pos = pos->next)
					n++;

				for (pos = record_head->next; pos != record_list; pos = pos->next)
				{
					int64_t fix_offset;

					record = list_entry(pos, KafkaRecord, list);
					fix_offset = offset + record->get_offset() - n + 1;
					record->set_offset(fix_offset);
				}
			}
		}
	}

	if (*size > 0)
	{
		return parse_message_set(buf, size, check_crcs, msg_vers,
								 record_list, uncompressed, toppar);
	}

	return 0;
}

static int parse_varint_bytes(void **buf, size_t *size,
							  void **str, size_t *str_len)
{
	int64_t len = 0;

	if (parse_varint_i64(buf, size, &len) >= 0)
	{
		if (len >= -1)
		{
			if (len <= 0)
			{
				*str = NULL;
				*str_len = 0;
				return 0;
			}

			if ((int64_t)*size >= len)
			{
				*str = *buf;
				*str_len = (size_t)len;
				*size -= len;
				*buf = (char *)*buf + len;
				return 0;
			}
		}
	}

	errno = EBADMSG;
	return -1;
}

struct KafkaBatchRecordHeader
{
	int64_t base_offset;
	int32_t length;
	int32_t partition_leader_epoch;
	int8_t	magic;
	int32_t crc;
	int16_t attributes;
	int32_t last_offset_delta;
	int64_t base_timestamp;
	int64_t max_timestamp;
	int64_t produce_id;
	int16_t producer_epoch;
	int32_t base_sequence;
	int32_t record_count;
};

int KafkaMessage::parse_message_record(void **buf, size_t *size,
									   kafka_record_t *record)
{
	int64_t length;
	int8_t attributes;
	int64_t timestamp_delta;
	int64_t offset_delta;
	int32_t hdr_size;

	if (parse_varint_i64(buf, size, &length) < 0)
		return -1;

	if (parse_i8(buf, size, &attributes) < 0)
		return -1;

	if (parse_varint_i64(buf, size, &timestamp_delta) < 0)
		return -1;

	if (parse_varint_i64(buf, size, &offset_delta) < 0)
		return -1;

	record->timestamp += timestamp_delta;
	record->offset += offset_delta;

	if (parse_varint_bytes(buf, size, &record->key, &record->key_len) < 0)
		return -1;

	if (parse_varint_bytes(buf, size, &record->value, &record->value_len) < 0)
		return -1;

	if (parse_varint_i32(buf, size, &hdr_size) < 0)
		return -1;

	for (int i = 0; i < hdr_size; ++i)
	{
		kafka_record_header_t *header;

		header = (kafka_record_header_t *)malloc(sizeof(kafka_record_header_t));
		if (!header)
			return -1;

		kafka_record_header_init(header);
		if (parse_varint_bytes(buf, size, &header->key, &header->key_len) < 0)
		{
			free(header);
			return -1;
		}

		if (parse_varint_bytes(buf, size, &header->value, &header->value_len) < 0)
		{
			kafka_record_header_deinit(header);
			free(header);
			return -1;
		}

		header->key_is_moved = 1;
		header->value_is_moved = 1;

		list_add_tail(&header->list, &record->header_list);
	}

	return record->offset < record->toppar->offset ? 1 : 0;
}

int KafkaMessage::parse_record_batch(void **buf, size_t *size,
									 bool check_crcs,
									 struct list_head *record_list,
									 KafkaBuffer *uncompressed,
									 KafkaToppar *toppar)
{
	KafkaBatchRecordHeader hdr;

	if (parse_i64(buf, size, &hdr.base_offset) < 0)
		return -1;

	if (parse_i32(buf, size, &hdr.length) < 0)
		return -1;

	if (parse_i32(buf, size, &hdr.partition_leader_epoch) < 0)
		return -1;

	if (parse_i8(buf, size, &hdr.magic) < 0)
		return -1;

	if (parse_i32(buf, size, &hdr.crc) < 0)
		return -1;

	if (check_crcs)
	{
		if (hdr.length > (int)*size + 9)
		{
			errno = EBADMSG;
			return -1;
		}

		if ((int)crc32c(0, (const void *)*buf, hdr.length - 9) != hdr.crc)
		{
			errno = EBADMSG;
			return -1;
		}
	}

	if (parse_i16(buf, size, &hdr.attributes) < 0)
		return -1;

	if (parse_i32(buf, size, &hdr.last_offset_delta) < 0)
		return -1;

	if (parse_i64(buf, size, &hdr.base_timestamp) < 0)
		return -1;

	if (parse_i64(buf, size, &hdr.max_timestamp) < 0)
		return -1;

	if (parse_i64(buf, size, &hdr.produce_id) < 0)
		return -1;

	if (parse_i16(buf, size, &hdr.producer_epoch) < 0)
		return -1;

	if (parse_i32(buf, size, &hdr.base_sequence) < 0)
		return -1;

	if (parse_i32(buf, size, &hdr.record_count) < 0)
		return -1;

	if (*size < (size_t)(hdr.length - 61 + 12))
		return 1;

	KafkaBlock block;

	if (hdr.attributes & 7)
	{
		if (uncompress_buf(*buf, hdr.length - 61 + 12, &block, hdr.attributes & 7) < 0)
			return -1;

		*buf = (char *)*buf + hdr.length - 61 + 12;
		*size -= hdr.length - 61 + 12;
	}

	void *p = *buf;
	size_t n = *size;

	if (block.get_len() > 0)
	{
		p = block.get_block();
		n = block.get_len();
	}

	for (int i = 0; i < hdr.record_count; ++i)
	{
		KafkaRecord *record = new KafkaRecord;
		record->set_offset(hdr.base_offset);
		record->set_timestamp(hdr.base_timestamp);
		record->get_raw_ptr()->key_is_moved = 1;
		record->get_raw_ptr()->value_is_moved = 1;
		record->get_raw_ptr()->toppar = toppar->get_raw_ptr();

		switch (parse_message_record(&p, &n, record->get_raw_ptr()))
		{
			case -1:
				delete record;
				return -1;
			case 0:
				list_add_tail(record->get_list(), record_list);
				break;
			default:
				delete record;
				break;
		}
	}

	if (hdr.attributes == 0)
	{
		*buf = p;
		*size = n;
	}

	if (block.get_len() > 0)
		uncompressed->add_item(std::move(block));

	return 0;
}

int KafkaMessage::parse_records(void **buf, size_t *size, bool check_crcs,
								KafkaBuffer *uncompressed, KafkaToppar *toppar)
{
	struct list_head *record_list = toppar->get_record();
	int msg_set_size = 0;

	if (parse_i32(buf, size, &msg_set_size) < 0)
		return -1;

	if (msg_set_size == 0)
		return 0;

	if (msg_set_size < 0)
		return -1;

	if (*size < 17)
		return -1;

	size_t msg_size = msg_set_size;

	while (msg_size > 16)
	{
		int ret = -1;
		char magic = ((char *)(*buf))[16];

		switch(magic)
		{
		case 0:
		case 1:
			ret = parse_message_set(buf, &msg_size, check_crcs,
									magic, record_list,
									uncompressed, toppar);
			break;

		case 2:
			ret = parse_record_batch(buf, &msg_size, check_crcs,
									 record_list, uncompressed, toppar);
			break;

		default:
			break;
		}

		if (ret > 0)
		{
			*size -= msg_set_size;
			*buf = (char *)*buf + msg_size;
			return 0;
		}
		else if (ret < 0)
			break;
	}

	*size -= msg_set_size;
	*buf = (char *)*buf + msg_size;
	return 0;
}

KafkaMessage::KafkaMessage()
{
	static struct Crc32cInitializer
	{
		Crc32cInitializer()
		{
			crc32c_global_init();
		}
	} initializer;

	this->parser = new kafka_parser_t;
	kafka_parser_init(this->parser);
	this->stream = new EncodeStream;
	this->api_type = Kafka_Unknown;
	this->correlation_id = 0;
	this->cur_size = 0;
}

KafkaMessage::~KafkaMessage()
{
	if (this->parser)
	{
		kafka_parser_deinit(this->parser);
		delete this->parser;
		delete this->stream;
	}
}

KafkaMessage::KafkaMessage(KafkaMessage&& msg) :
	ProtocolMessage(std::move(msg))
{
	this->parser = msg.parser;
	this->stream = msg.stream;
	msg.parser = NULL;
	msg.stream = NULL;

	this->msgbuf = std::move(msg.msgbuf);
	this->headbuf = std::move(msg.headbuf);

	this->toppar_list = std::move(msg.toppar_list);
	this->serialized = std::move(msg.serialized);
	this->uncompressed = std::move(msg.uncompressed);

	this->api_type = msg.api_type;
	msg.api_type = Kafka_Unknown;

	this->compress_env = msg.compress_env;
	msg.compress_env = NULL;

	this->cur_size = msg.cur_size;
	msg.cur_size = 0;
}

KafkaMessage& KafkaMessage::operator= (KafkaMessage &&msg)
{
	if (this != &msg)
	{
		*(ProtocolMessage *)this = std::move(msg);

		if (this->parser)
		{
			kafka_parser_deinit(this->parser);
			delete this->parser;
			delete this->stream;
		}

		this->parser = msg.parser;
		this->stream = msg.stream;
		msg.parser = NULL;
		msg.stream = NULL;

		this->msgbuf = std::move(msg.msgbuf);
		this->headbuf = std::move(msg.headbuf);

		this->toppar_list = std::move(msg.toppar_list);
		this->serialized = std::move(msg.serialized);
		this->uncompressed = std::move(msg.uncompressed);

		this->api_type = msg.api_type;
		msg.api_type = Kafka_Unknown;

		this->compress_env = msg.compress_env;
		msg.compress_env = NULL;

		this->cur_size = msg.cur_size;
		msg.cur_size = 0;
	}

	return *this;
}

int KafkaMessage::encode_message(int api_type, struct iovec vectors[], int max)
{
	const auto it = this->encode_func_map.find(api_type);

	if (it == this->encode_func_map.cend())
		return -1;

	return it->second(vectors, max);
}

static int kafka_api_get_max_ver(int api_type)
{
	switch (api_type)
	{
	case Kafka_Metadata:
		return 4;
	case Kafka_Produce:
		return 7;
	case Kafka_Fetch:
		return 11;
	case Kafka_FindCoordinator:
		return 2;
	case Kafka_JoinGroup:
		return 5;
	case Kafka_SyncGroup:
		return 3;
	case Kafka_Heartbeat:
		return 3;
	case Kafka_OffsetFetch:
		return 1;
	case Kafka_OffsetCommit:
		return 7;
	case Kafka_ListOffsets:
		return 1;
	case Kafka_LeaveGroup:
		return 1;
	case Kafka_ApiVersions:
		return 0;
	case Kafka_SaslHandshake:
		return 1;
	case Kafka_SaslAuthenticate:
		return 0;
	case Kafka_DescribeGroups:
		return 0;
	default:
		return 0;
	}
}

static int kafka_get_api_version(const kafka_api_t *api, const KafkaConfig& conf,
								 int api_type, int max_ver, int message_version)
{
	int min_ver = 0;

	if (api_type == Kafka_Produce)
	{
		if (message_version == 2)
			min_ver = 3;
		else if (message_version == 1)
			min_ver = 1;

		if (conf.get_compress_type() == Kafka_Zstd)
			min_ver = 7;
	}

	return kafka_broker_get_api_version(api, api_type, min_ver, max_ver);
}

int KafkaMessage::encode_head()
{
	if (this->api_type == Kafka_ApiVersions)
		this->api_version = 0;
	else
	{
		int max_ver = kafka_api_get_max_ver(this->api_type);

		if (this->api->features & KAFKA_FEATURE_MSGVER2)
			this->message_version = 2;
		else if (this->api->features & KAFKA_FEATURE_MSGVER1)
			this->message_version = 1;
		else
			this->message_version = 0;

		if (this->config.get_compress_type() == Kafka_Lz4 &&
			!(this->api->features & KAFKA_FEATURE_LZ4))
		{
			this->config.set_compress_type(Kafka_NoCompress);
		}

		if (this->config.get_compress_type() == Kafka_Zstd &&
			!(this->api->features & KAFKA_FEATURE_ZSTD))
		{
			this->config.set_compress_type(Kafka_NoCompress);
		}

		this->api_version = kafka_get_api_version(this->api, this->config,
												  this->api_type, max_ver,
												  this->message_version);
	}

	if (this->api_version < 0)
		return -1;

	append_i32(this->headbuf, 0);
	append_i16(this->headbuf, this->api_type);
	append_i16(this->headbuf, this->api_version);
	append_i32(this->headbuf, this->correlation_id);
	append_string(this->headbuf, this->config.get_client_id());

	return 0;
}

int KafkaMessage::encode(struct iovec vectors[], int max)
{
	if (encode_head() < 0)
		return -1;

	int n = encode_message(this->api_type, vectors + 1, max - 1);
	if (n < 0)
		return -1;

	int msg_size = this->headbuf.size() + this->cur_size - 4;
	*(int32_t *)this->headbuf.c_str() = htonl(msg_size);

	vectors[0].iov_base = (void *)this->headbuf.c_str();
	vectors[0].iov_len = this->headbuf.size();

	return n + 1;
}

int KafkaMessage::append(const void *buf, size_t *size)
{
	int ret = kafka_parser_append_message(buf, size, this->parser);

	if (ret >= 0)
	{
		this->cur_size += *size;
		if (this->cur_size > this->size_limit)
		{
			errno = EMSGSIZE;
			ret = -1;
		}
	}
	else if (ret == -2)
	{
		errno = EBADMSG;
		ret = -1;
	}

	return ret;
}

static int kafka_compress_prepare(int compress_type, void **env,
								  KafkaBlock *block)
{
	z_stream *c_stream;
	KafkaBuffer *snappy_buffer;
	size_t lz4_out_len;
	LZ4F_errorCode_t lz4_r;
	LZ4F_cctx *lz4_cctx = NULL;
	ZSTD_CStream *zstd_cctx;
	size_t zstd_r;

	switch (compress_type)
	{
	case Kafka_Gzip:
		c_stream = new z_stream;
		c_stream->zalloc = (alloc_func)0;
		c_stream->zfree = (free_func)0;
		c_stream->opaque = (voidpf)0;
		if (deflateInit2(c_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 | 16,
						 8, Z_DEFAULT_STRATEGY) != Z_OK)
		{
			delete c_stream;
			errno = EBADMSG;
			return -1;
		}

		c_stream->avail_in = 0;
		c_stream->avail_out = 0;
		c_stream->total_in = 0;

		*env = (void *)c_stream;
		break;

	case Kafka_Snappy:
		snappy_buffer = new KafkaBuffer;
		*env = (void *)snappy_buffer;
		break;

	case Kafka_Lz4:
		lz4_r = LZ4F_createCompressionContext(&lz4_cctx, LZ4F_VERSION);
		if (LZ4F_isError(lz4_r))
		{
			LZ4F_freeCompressionContext(lz4_cctx);
			errno = EBADMSG;
			return -1;
		}

		lz4_out_len = LZ4F_HEADER_SIZE_MAX;

		if (!block->allocate(lz4_out_len))
		{
			LZ4F_freeCompressionContext(lz4_cctx);
			return -1;
		}

		lz4_r = LZ4F_compressBegin(lz4_cctx, block->get_block(),
								   block->get_len(), &kPrefs);
		if (LZ4F_isError(lz4_r))
		{
			LZ4F_freeCompressionContext(lz4_cctx);
			errno = EBADMSG;
			return -1;
		}

		block->set_len(lz4_r);

		*env = (void *)lz4_cctx;
		break;

	case Kafka_Zstd:
		zstd_cctx = ZSTD_createCStream();
		if (!zstd_cctx)
			return -1;

		zstd_r = ZSTD_initCStream(zstd_cctx, ZSTD_CLEVEL_DEFAULT);
		if (ZSTD_isError(zstd_r))
		{
			ZSTD_freeCStream(zstd_cctx);
			errno = EBADMSG;
			return -1;
		}

		*env = (void *)zstd_cctx;
		break;

	default:
		return 0;
	}

	return 0;
}

static int kafka_compress_finish(int compress_type, void *env,
								 KafkaBuffer *buffer, int *addon)
{
	int gzip_err;
	LZ4F_cctx *lz4_cctx;
	z_stream *c_stream;
	size_t out_len;
	KafkaBuffer *snappy_buffer;
	LZ4F_errorCode_t lz4_r;
	ZSTD_CStream *zstd_cctx;
	size_t zstd_r;
	ZSTD_outBuffer out;
	KafkaBlock block;
	size_t zstd_end_bufsize = ZSTD_compressBound(buffer->get_size());

	switch (compress_type)
	{
	case Kafka_Gzip:
		c_stream = static_cast<z_stream *>(env);
		out_len = c_stream->total_out;
		for(;;)
		{
			if (c_stream->avail_out == 0)
			{
				block.allocate(1024);
				c_stream->next_out = (Bytef *)block.get_block();
				c_stream->avail_out = 1024;
			}

			gzip_err = deflate(c_stream, Z_FINISH);

			if (gzip_err == Z_STREAM_END)
				break;

			if (gzip_err != Z_OK)
			{
				delete c_stream;
				errno = EBADMSG;
				return -1;
			}
			else if (block.get_len() > 0)
			{
				size_t use_bytes = block.get_len() - c_stream->avail_out;

				block.set_len(use_bytes);
				buffer->add_item(std::move(block));
				*addon += use_bytes;
			}
		}

		if (deflateEnd(c_stream) != Z_OK)
		{
			delete c_stream;
			errno = EBADMSG;
			return -1;
		}

		if (block.get_len() > 0)
		{
			size_t use_bytes = block.get_len() - c_stream->avail_out;
			block.set_len(use_bytes);
			buffer->add_item(std::move(block));
			*addon += use_bytes;
		}
		else
		{
			KafkaBlock *b = buffer->get_block_tail();
			size_t use_bytes = b->get_len() - c_stream->avail_out;
			int remainer = b->get_len() - use_bytes;

			b->set_len(use_bytes);
			*addon += -remainer;
		}

		delete c_stream;
		break;

	case Kafka_Snappy:
		snappy_buffer = static_cast<KafkaBuffer *>(env);
		{
			KafkaBuffer kafka_buffer_sink;
			KafkaSnappySource source(snappy_buffer);
			KafkaSnappySink sink(&kafka_buffer_sink);

			if (snappy::Compress(&source, &sink) < 0)
			{
				delete snappy_buffer;
				errno = EBADMSG;
				return -1;
			}

			size_t pre_n = buffer->get_size();

			buffer->list_splice(&kafka_buffer_sink);
			*addon = buffer->get_size() - pre_n;
		}

		delete snappy_buffer;
		break;

	case Kafka_Lz4:
		lz4_cctx = static_cast<LZ4F_cctx *>(env);
		out_len = LZ4F_compressBound(0, &kPrefs);
		if (!block.allocate(out_len))
		{
			LZ4F_freeCompressionContext(lz4_cctx);
			return -1;
		}

		lz4_r = LZ4F_compressEnd(lz4_cctx, block.get_block(), block.get_len(), NULL);
		if (LZ4F_isError(lz4_r))
		{
			LZ4F_freeCompressionContext(lz4_cctx);
			errno = EBADMSG;
			return -1;
		}

		block.set_len(lz4_r);
		buffer->add_item(std::move(block));
		*addon = lz4_r;
		LZ4F_freeCompressionContext(lz4_cctx);
		break;

	case Kafka_Zstd:
		zstd_cctx = static_cast<ZSTD_CStream *>(env);
		if (!block.allocate(zstd_end_bufsize))
			return -1;

		out.dst = block.get_block();
		out.pos = 0;
		out.size = 1024000;
		zstd_r = ZSTD_endStream(zstd_cctx, &out);
		if (ZSTD_isError(zstd_r) || zstd_r > 0)
		{
			ZSTD_freeCStream(zstd_cctx);
			errno = EBADMSG;
			return -1;
		}

		block.set_len(out.pos);
		buffer->add_item(std::move(block));
		*addon = out.pos;
		ZSTD_freeCStream(zstd_cctx);
		break;

	default:
		return 0;
	}

	return 0;
}

KafkaRequest::KafkaRequest()
{
	using namespace std::placeholders;
	this->encode_func_map[Kafka_Metadata] = std::bind(&KafkaRequest::encode_metadata, this, _1, _2);
	this->encode_func_map[Kafka_Produce] = std::bind(&KafkaRequest::encode_produce, this, _1, _2);
	this->encode_func_map[Kafka_Fetch] = std::bind(&KafkaRequest::encode_fetch, this, _1, _2);
	this->encode_func_map[Kafka_FindCoordinator] = std::bind(&KafkaRequest::encode_findcoordinator, this, _1, _2);
	this->encode_func_map[Kafka_JoinGroup] = std::bind(&KafkaRequest::encode_joingroup, this, _1, _2);
	this->encode_func_map[Kafka_SyncGroup] = std::bind(&KafkaRequest::encode_syncgroup, this, _1, _2);
	this->encode_func_map[Kafka_Heartbeat] = std::bind(&KafkaRequest::encode_heartbeat, this, _1, _2);
	this->encode_func_map[Kafka_OffsetFetch] = std::bind(&KafkaRequest::encode_offsetfetch, this, _1, _2);
	this->encode_func_map[Kafka_OffsetCommit] = std::bind(&KafkaRequest::encode_offsetcommit, this, _1, _2);
	this->encode_func_map[Kafka_ListOffsets] = std::bind(&KafkaRequest::encode_listoffset, this, _1, _2);
	this->encode_func_map[Kafka_LeaveGroup] = std::bind(&KafkaRequest::encode_leavegroup, this, _1, _2);
	this->encode_func_map[Kafka_ApiVersions] = std::bind(&KafkaRequest::encode_apiversions, this, _1, _2);
	this->encode_func_map[Kafka_SaslHandshake] = std::bind(&KafkaRequest::encode_saslhandshake, this, _1, _2);
	this->encode_func_map[Kafka_SaslAuthenticate] = std::bind(&KafkaRequest::encode_saslauthenticate, this, _1, _2);
}

int KafkaRequest::encode_produce(struct iovec vectors[], int max)
{
	this->stream->reset(vectors, max);

	//transaction_id
	if (this->api_version >= 3)
		append_nullable_string(this->msgbuf, "", 0);

	append_i16(this->msgbuf, this->config.get_produce_acks());
	append_i32(this->msgbuf, this->config.get_produce_timeout());

	int topic_cnt = 0;
	this->toppar_list.rewind();
	KafkaToppar *toppar;

	while ((toppar = this->toppar_list.get_next()) != NULL)
	{
		std::string topic_header;
		KafkaBlock header_block;
		int record_flag = -1;

		append_string(topic_header, toppar->get_topic());
		append_i32(topic_header, 1);
		append_i32(topic_header, toppar->get_partition());
		append_i32(topic_header, 0); // recordset length

		if (!header_block.set_block((void *)topic_header.c_str(),
									topic_header.size()))
		{
			return -1;
		}

		void *recordset_size_ptr = (void *)((char *)header_block.get_block() +
											header_block.get_len() - 4);

		int64_t first_timestamp = 0;
		int64_t max_timestamp = 0;
		const int MSGV2HSize = (8 + 4 + 4 + 1 + 4 + 2 + 4 + 8 + 8 + 8 + 2 + 4 + 4);
		int batch_length = 0;

		if (this->message_version == 2)
			batch_length = MSGV2HSize - (8 + 4);

		size_t cur_serialized_len = this->serialized.get_size();
		int batch_cnt = 0;

		toppar->save_record_startpos();
		KafkaRecord *record;
		while ((record = toppar->get_record_next()) != NULL)
		{
			KafkaBlock compress_block;
			KafkaBlock record_block;
			struct timespec ts;

			if (record->get_timestamp() == 0)
			{
				clock_gettime(CLOCK_REALTIME, &ts);
				record->set_timestamp((ts.tv_sec * 1000000000 +
									   ts.tv_nsec) / 1000 / 1000);
			}

			if (batch_cnt == 0)
			{
				if (kafka_compress_prepare(this->config.get_compress_type(),
										   &this->compress_env,
										   &compress_block) < 0)
				{
					return -1;
				}

				first_timestamp = record->get_timestamp();
			}

			int ret = append_record(&record_block, record, batch_cnt,
									this->message_version, this->config,
									first_timestamp, this->compress_env,
									batch_length);

			if (ret < 0)
				return -1;

			if (ret > 0)
			{
				toppar->record_rollback();
				toppar->save_record_endpos();
				if (record_flag < 0)
				{
					errno = EMSGSIZE;
					return -1;
				}
				else
					record_flag = 1;

				break;
			}

			if (batch_cnt == 0)
			{
				this->serialized.add_item(std::move(header_block));
				cur_serialized_len = this->serialized.get_size();
				this->serialized.set_insert_pos();

				if (compress_block.get_len() > 0)
					this->serialized.add_item(std::move(compress_block));
			}

			if (record_block.get_len() > 0)
				this->serialized.add_item(std::move(record_block));

			record_flag = 0;
			toppar->save_record_endpos();

			max_timestamp = record->get_timestamp();
			++batch_cnt;

			batch_length += this->serialized.get_size() - cur_serialized_len;
			cur_serialized_len = this->serialized.get_size();
		}

		if (record_flag < 0)
			continue;

		if (this->message_version == 2)
		{
			if (this->config.get_compress_type() != Kafka_NoCompress)
			{
				int addon = 0;

				if (kafka_compress_finish(this->config.get_compress_type(),
										  this->compress_env, &this->serialized, &addon) < 0)
				{
					return -1;
				}

				batch_length += addon;
			}

			std::string record_header;

			append_i64(record_header, 0);
			append_i32(record_header, batch_length);
			append_i32(record_header, 0);
			append_i8(record_header, 2); //magic

			uint32_t crc_32 = 0;
			size_t crc32_offset = record_header.size();

			append_i32(record_header, crc_32);
			append_i16(record_header, this->config.get_compress_type());
			append_i32(record_header, batch_cnt - 1);
			append_i64(record_header, first_timestamp);
			append_i64(record_header, max_timestamp);
			append_i64(record_header, -1); //produce_id
			append_i16(record_header, -1);
			append_i32(record_header, -1);
			append_i32(record_header, batch_cnt);

			KafkaBlock *header_block = new KafkaBlock;

			if (!header_block->set_block((void *)record_header.c_str(),
										 record_header.size()))
			{
				delete header_block;
				return -1;
			}

			char *crc_ptr = (char *)header_block->get_block() + crc32_offset;

			this->serialized.insert_list(header_block);

			crc_32 = crc32c(crc_32, (const void *)(crc_ptr + 4),
							header_block->get_len() - crc32_offset - 4);

			this->serialized.block_insert_rewind();
			KafkaBlock *block;
			while ((block = this->serialized.get_block_insert_next()) != NULL)
				crc_32 = crc32c(crc_32, block->get_block(), block->get_len());

			*(uint32_t *)crc_ptr = htonl(crc_32);
			*(uint32_t *)recordset_size_ptr = htonl(batch_length + 4 + 8);
		}
		else
		{
			if (this->config.get_compress_type() != Kafka_NoCompress)
			{
				int addon = 0;

				if (kafka_compress_finish(this->config.get_compress_type(),
										  this->compress_env, &this->serialized, &addon) < 0)
				{
					return -1;
				}

				batch_length += addon;

				int message_size = 4 + 1 + 1 + 4 + 4 + batch_length;

				if (this->message_version == 1)
					message_size += 8;

				std::string wrap_header;

				append_i64(wrap_header, 0);
				append_i32(wrap_header, message_size);

				int crc_32 = crc32(0, NULL, 0);
				size_t crc32_offset = wrap_header.size();

				append_i32(wrap_header, crc_32);
				append_i8(wrap_header, this->message_version);
				append_i8(wrap_header, this->config.get_compress_type());

				if (this->message_version == 1)
					append_i64(wrap_header, first_timestamp);

				append_bytes(wrap_header, "");
				append_i32(wrap_header, batch_length);
				const char *crc_ptr = (const char *)wrap_header.c_str() + crc32_offset;

				crc_32 = crc32(crc_32, (Bytef *)(crc_ptr + 4),
							   wrap_header.size() - crc32_offset - 4);

				this->serialized.block_insert_rewind();
				KafkaBlock *block;

				while ((block = this->serialized.get_block_insert_next()) != NULL)
					crc_32 = crc32(crc_32, (Bytef *)block->get_block(), block->get_len());

				*(uint32_t *)crc_ptr = htonl(crc_32);

				KafkaBlock *wrap_block =  new KafkaBlock;

				if (!wrap_block->set_block((void *)wrap_header.c_str(),
										   wrap_header.size()))
				{
					delete wrap_block;
					return -1;
				}

				this->serialized.insert_list(wrap_block);
				*(uint32_t *)recordset_size_ptr = htonl(message_size + 8 + 4);
			}
			else
				*(uint32_t *)recordset_size_ptr = htonl(batch_length);
		}

		++topic_cnt;
	}

	append_i32(this->msgbuf, topic_cnt);
	this->cur_size += this->msgbuf.size();
	this->stream->append_nocopy(this->msgbuf.c_str(), this->msgbuf.size());

	vectors[0].iov_base = (void *)this->msgbuf.c_str();
	vectors[0].iov_len = this->msgbuf.size();

	KafkaBlock *block = this->serialized.get_block_first();

	while (block)
	{
		this->stream->append_nocopy((const char *)block->get_block(),
									block->get_len());
		this->cur_size += block->get_len();
		block = this->serialized.get_block_next();
	}

	return this->stream->size();
}

int KafkaRequest::encode_fetch(struct iovec vectors[], int max)
{
	append_i32(this->msgbuf, -1);
	append_i32(this->msgbuf, this->config.get_fetch_timeout());
	append_i32(this->msgbuf, this->config.get_fetch_min_bytes());

	if (this->api_version >= 3)
		append_i32(this->msgbuf, this->config.get_fetch_max_bytes());

	//isolation_level
	if (this->api_version >= 4)
		append_i8(this->msgbuf, 0);

	if (this->api_version >= 7)
	{
		//sessionid
		append_i32(this->msgbuf, 0);
		//epoch
		append_i32(this->msgbuf, -1);
	}

	int topic_cnt_pos = this->msgbuf.size();

	append_i32(this->msgbuf, 0);

	int topic_cnt = 0;
	this->toppar_list.rewind();
	KafkaToppar *toppar;

	while ((toppar = this->toppar_list.get_next()) != NULL)
	{
		append_string(this->msgbuf, toppar->get_topic());
		append_i32(this->msgbuf, 1);
		append_i32(this->msgbuf, toppar->get_partition());

		//CurrentLeaderEpoch
		if (this->api_version >= 9)
			append_i32(this->msgbuf, -1);

		append_i64(this->msgbuf, toppar->get_offset());

		//LogStartOffset
		if (this->api_version >= 5)
			append_i64(this->msgbuf, -1);

		append_i32(this->msgbuf, this->config.get_fetch_msg_max_bytes());
		++topic_cnt;
	}

	*(uint32_t *)(this->msgbuf.c_str() + topic_cnt_pos) = htonl(topic_cnt);

	//Length of the ForgottenTopics list
	if (this->api_version >= 7)
		append_i32(this->msgbuf, 0);

	//rackid
	if (this->api_version >= 11)
	{
		if (this->config.get_rack_id())
			append_compact_string(this->msgbuf, this->config.get_rack_id());
		else
			append_string(this->msgbuf, "");
	}

	this->cur_size = this->msgbuf.size();

	vectors[0].iov_base = (void *)this->msgbuf.c_str();
	vectors[0].iov_len = this->msgbuf.size();
	return 1;
}

int KafkaRequest::encode_metadata(struct iovec vectors[], int max)
{
	int topic_cnt_pos = this->msgbuf.size();

	if (this->api_version >= 1)
		append_i32(this->msgbuf, -1);
	else
		append_i32(this->msgbuf, 0);

	this->meta_list.rewind();
	KafkaMeta *meta;
	int topic_cnt = 0;

	while ((meta = this->meta_list.get_next()) != NULL)
	{
		append_string(this->msgbuf, meta->get_topic());
		++topic_cnt;
	}

	if (this->api_version >= 4)
	{
		append_bool(this->msgbuf,
					this->config.get_allow_auto_topic_creation());
	}

	*(uint32_t *)(this->msgbuf.c_str() + topic_cnt_pos) = htonl(topic_cnt);
	this->cur_size = this->msgbuf.size();

	vectors[0].iov_base = (void *)this->msgbuf.c_str();
	vectors[0].iov_len = this->msgbuf.size();
	return 1;
}

int KafkaRequest::encode_findcoordinator(struct iovec vectors[], int max)
{
	append_string(this->msgbuf, this->cgroup.get_group());

	//coordinator key type
	if (this->api_version >= 1)
		append_i8(this->msgbuf, 0);

	this->cur_size = this->msgbuf.size();

	vectors[0].iov_base = (void *)this->msgbuf.c_str();
	vectors[0].iov_len = this->msgbuf.size();
	return 1;
}

static std::string kafka_cgroup_gen_metadata(KafkaMetaList& meta_list)
{
	std::string metadata;
	int meta_pos;
	int meta_cnt = 0;
	meta_list.rewind();
	KafkaMeta *meta;

	append_i16(metadata, 2); // version
	meta_pos = metadata.size();
	append_i32(metadata, 0);

	while ((meta = meta_list.get_next()) != NULL)
	{
		append_string(metadata, meta->get_topic());
		meta_cnt++;
	}

	*(uint32_t *)(metadata.c_str() + meta_pos) = htonl(meta_cnt);

	//UserData empty
	append_bytes(metadata, "");

	return metadata;
}

int KafkaRequest::encode_joingroup(struct iovec vectors[], int max)
{
	append_string(this->msgbuf, this->cgroup.get_group());
	append_i32(this->msgbuf, this->config.get_session_timeout());

	if (this->api_version >= 1)
		append_i32(this->msgbuf, this->config.get_rebalance_timeout());

	//member_id
	append_string(this->msgbuf, this->cgroup.get_member_id());

	//group_instance_id
	if (this->api_version >= 5)
		append_nullable_string(this->msgbuf, "", 0);

	append_string(this->msgbuf, this->cgroup.get_protocol_type());
	int protocol_pos = this->msgbuf.size();
	append_i32(this->msgbuf, 0);

	int protocol_cnt = 0;
	struct list_head *pos;
	kafka_group_protocol_t *group_protocol;
	list_for_each(pos, this->cgroup.get_group_protocol())
	{
		++protocol_cnt;
		group_protocol = list_entry(pos, kafka_group_protocol_t, list);
		append_string(this->msgbuf, group_protocol->protocol_name);
		append_bytes(this->msgbuf,
					 kafka_cgroup_gen_metadata(this->meta_list));
	}

	*(uint32_t *)(this->msgbuf.c_str() + protocol_pos) = htonl(protocol_cnt);

	this->cur_size = this->msgbuf.size();

	vectors[0].iov_base = (void *)this->msgbuf.c_str();
	vectors[0].iov_len = this->msgbuf.size();
	return 1;
}

std::string KafkaMessage::get_member_assignment(kafka_member_t *member)
{
	std::string assignment;
	//version
	append_i16(assignment, 2);

	size_t topic_cnt_pos = assignment.size();
	append_i32(assignment, 0);

	struct list_head *pos;
	KafkaToppar *toppar;
	int topic_cnt = 0;

	list_for_each(pos, &member->assigned_toppar_list)
	{
		toppar = list_entry(pos, KafkaToppar, list);
		append_string(assignment, toppar->get_topic());
		append_i32(assignment, 1);
		append_i32(assignment, toppar->get_partition());
		++topic_cnt;
	}

	//userdata
	append_bytes(assignment, "");

	*(uint32_t *)(assignment.c_str() + topic_cnt_pos) = htonl(topic_cnt);

	return assignment;
}

int KafkaRequest::encode_syncgroup(struct iovec vectors[], int max)
{
	append_string(this->msgbuf, this->cgroup.get_group());
	append_i32(this->msgbuf, this->cgroup.get_generation_id());
	append_string(this->msgbuf, this->cgroup.get_member_id());

	//group_instance_id
	if (this->api_version >= 3)
		append_nullable_string(this->msgbuf, "", 0);

	if (this->cgroup.is_leader())
	{
		append_i32(this->msgbuf, this->cgroup.get_member_elements());
		for (int i = 0; i < this->cgroup.get_member_elements(); ++i)
		{
			kafka_member_t *member = this->cgroup.get_members()[i];
			append_string(this->msgbuf, member->member_id);
			append_bytes(this->msgbuf, std::move(get_member_assignment(member)));
		}
	}
	else
		append_i32(this->msgbuf, 0);

	this->cur_size = this->msgbuf.size();

	vectors[0].iov_base = (void *)this->msgbuf.c_str();
	vectors[0].iov_len = this->msgbuf.size();
	return 1;
}

int KafkaRequest::encode_leavegroup(struct iovec vectors[], int max)
{
	append_string(this->msgbuf, this->cgroup.get_group());
	append_string(this->msgbuf, this->cgroup.get_member_id());

	this->cur_size = this->msgbuf.size();

	vectors[0].iov_base = (void *)this->msgbuf.c_str();
	vectors[0].iov_len = this->msgbuf.size();
	return 1;
}

int KafkaRequest::encode_listoffset(struct iovec vectors[], int max)
{
	append_i32(this->msgbuf, -1);

	int topic_cnt = 0;
	int topic_cnt_pos = this->msgbuf.size();
	append_i32(this->msgbuf, 0);

	struct list_head *pos;
	KafkaToppar *toppar;

	list_for_each(pos, this->toppar_list.get_head())
	{
		toppar = this->toppar_list.get_entry(pos);
		append_string(this->msgbuf, toppar->get_topic());

		append_i32(this->msgbuf, 1);
		append_i32(this->msgbuf, toppar->get_partition());
		append_i64(this->msgbuf, toppar->get_offset_timestamp());

		if (this->api_version == 0)
			append_i32(this->msgbuf, 1);

		++topic_cnt;
	}

	*(uint32_t *)(this->msgbuf.c_str() + topic_cnt_pos) = htonl(topic_cnt);
	this->cur_size = this->msgbuf.size();

	vectors[0].iov_base = (void *)this->msgbuf.c_str();
	vectors[0].iov_len = this->msgbuf.size();
	return 1;
}

int KafkaRequest::encode_offsetfetch(struct iovec vectors[], int max)
{
	append_string(this->msgbuf, this->cgroup.get_group());

	int topic_cnt = 0;
	int topic_cnt_pos = this->msgbuf.size();
	append_i32(this->msgbuf, 0);

	this->cgroup.assigned_toppar_rewind();
	KafkaToppar *toppar;

	while ((toppar = this->cgroup.get_assigned_toppar_next()) != NULL)
	{
		append_string(this->msgbuf, toppar->get_topic());
		append_i32(this->msgbuf, 1);
		append_i32(this->msgbuf, toppar->get_partition());
		++topic_cnt;
	}

	*(uint32_t *)(this->msgbuf.c_str() + topic_cnt_pos) = htonl(topic_cnt);

	this->cur_size = this->msgbuf.size();

	vectors[0].iov_base = (void *)this->msgbuf.c_str();
	vectors[0].iov_len = this->msgbuf.size();
	return 1;
}

int KafkaRequest::encode_offsetcommit(struct iovec vectors[], int max)
{
	append_string(this->msgbuf, this->cgroup.get_group());

	if (this->api_version >= 1)
	{
		append_i32(this->msgbuf, this->cgroup.get_generation_id());
		append_string(this->msgbuf, this->cgroup.get_member_id());
	}

	//GroupInstanceId
	if (this->api_version >= 7)
		append_nullable_string(this->msgbuf, "", 0);

	//RetentionTime
	if (this->api_version >= 2 && this->api_version <= 4)
		append_i64(this->msgbuf, -1);

	int toppar_cnt = 0;
	int toppar_cnt_pos = this->msgbuf.size();
	append_i32(this->msgbuf, 0);

	this->toppar_list.rewind();
	KafkaToppar *toppar;

	while ((toppar = this->toppar_list.get_next()) != NULL)
	{
		append_string(this->msgbuf, toppar->get_topic());
		append_i32(this->msgbuf, 1);
		append_i32(this->msgbuf, toppar->get_partition());
		append_i64(this->msgbuf, toppar->get_offset() + 1);

		if (this->api_version >= 6)
			append_i32(this->msgbuf, -1);

		if (this->api_version == 1)
			append_i64(this->msgbuf, -1);

		append_nullable_string(this->msgbuf, "", 0);
		++toppar_cnt;
	}

	*(uint32_t *)(this->msgbuf.c_str() + toppar_cnt_pos) = htonl(toppar_cnt);

	this->cur_size = this->msgbuf.size();

	vectors[0].iov_base = (void *)this->msgbuf.c_str();
	vectors[0].iov_len = this->msgbuf.size();
	return 1;
}

int KafkaRequest::encode_heartbeat(struct iovec vectors[], int max)
{
	append_string(this->msgbuf, this->cgroup.get_group());
	append_i32(this->msgbuf, this->cgroup.get_generation_id());
	append_string(this->msgbuf, this->cgroup.get_member_id());

	//group_instance_id
	if (this->api_version >= 3)
		append_nullable_string(this->msgbuf, "", 0);

	this->cur_size = this->msgbuf.size();

	vectors[0].iov_base = (void *)this->msgbuf.c_str();
	vectors[0].iov_len = this->msgbuf.size();
	return 1;
}

int KafkaRequest::encode_apiversions(struct iovec vectors[], int max)
{
	return 0;
}

int KafkaRequest::encode_saslhandshake(struct iovec vectors[], int max)
{
	append_string(this->msgbuf, this->config.get_sasl_mech());

	this->cur_size = this->msgbuf.size();

	vectors[0].iov_base = (void *)this->msgbuf.c_str();
	vectors[0].iov_len = this->msgbuf.size();
	return 1;
}

int KafkaRequest::encode_saslauthenticate(struct iovec vectors[], int max)
{
	append_bytes(this->msgbuf, this->sasl->buf, this->sasl->bsize);

	this->cur_size = this->msgbuf.size();

	vectors[0].iov_base = (void *)this->msgbuf.c_str();
	vectors[0].iov_len = this->msgbuf.size();
	return 1;
}

KafkaResponse::KafkaResponse()
{
	using namespace std::placeholders;
	this->parse_func_map[Kafka_Metadata] = std::bind(&KafkaResponse::parse_metadata, this, _1, _2);
	this->parse_func_map[Kafka_Produce] = std::bind(&KafkaResponse::parse_produce, this, _1, _2);
	this->parse_func_map[Kafka_Fetch] = std::bind(&KafkaResponse::parse_fetch, this, _1, _2);
	this->parse_func_map[Kafka_FindCoordinator] = std::bind(&KafkaResponse::parse_findcoordinator, this, _1, _2);
	this->parse_func_map[Kafka_JoinGroup] = std::bind(&KafkaResponse::parse_joingroup, this, _1, _2);
	this->parse_func_map[Kafka_SyncGroup] = std::bind(&KafkaResponse::parse_syncgroup, this, _1, _2);
	this->parse_func_map[Kafka_Heartbeat] = std::bind(&KafkaResponse::parse_heartbeat, this, _1, _2);
	this->parse_func_map[Kafka_OffsetFetch] = std::bind(&KafkaResponse::parse_offsetfetch, this, _1, _2);
	this->parse_func_map[Kafka_OffsetCommit] = std::bind(&KafkaResponse::parse_offsetcommit, this, _1, _2);
	this->parse_func_map[Kafka_ListOffsets] = std::bind(&KafkaResponse::parse_listoffset, this, _1, _2);
	this->parse_func_map[Kafka_LeaveGroup] = std::bind(&KafkaResponse::parse_leavegroup, this, _1, _2);
	this->parse_func_map[Kafka_ApiVersions] = std::bind(&KafkaResponse::parse_apiversions, this, _1, _2);
	this->parse_func_map[Kafka_SaslHandshake] = std::bind(&KafkaResponse::parse_saslhandshake, this, _1, _2);
	this->parse_func_map[Kafka_SaslAuthenticate] = std::bind(&KafkaResponse::parse_saslauthenticate, this, _1, _2);
}

int KafkaResponse::parse_response()
{
	auto it = this->parse_func_map.find(this->api_type);

	if (it == this->parse_func_map.end())
	{
		errno = EPROTO;
		return -1;
	}

	void *buf = this->parser->msgbuf;
	size_t size = this->parser->message_size;
	int32_t correlation_id;

	if (parse_i32(&buf, &size, &correlation_id) < 0)
		return -1;

	this->correlation_id = correlation_id;

	int ret = it->second(&buf, &size);

	if (ret < 0)
		return -1;

	if (size != 0)
	{
		errno = EBADMSG;
		return -1;
	}

	return ret;
}

static int kafka_meta_parse_broker(void **buf, size_t *size,
								   int api_version,
								   KafkaBrokerList *broker_list)
{
	int32_t broker_cnt;

	CHECK_RET(parse_i32(buf, size, &broker_cnt));

	if (broker_cnt < 0)
	{
		errno = EBADMSG;
		return -1;
	}

	for (int i = 0; i < broker_cnt; ++i)
	{
		KafkaBroker broker;
		kafka_broker_t *ptr = broker.get_raw_ptr();

		CHECK_RET(parse_i32(buf, size, &ptr->node_id));
		CHECK_RET(parse_string(buf, size, &ptr->host));
		CHECK_RET(parse_i32(buf, size, &ptr->port));

		if (api_version >= 1)
			CHECK_RET(parse_string(buf, size, &ptr->rack));

		broker_list->rewind();
		KafkaBroker *last;

		while ((last = broker_list->get_next()) != NULL)
		{
			if (last->get_node_id() == broker.get_node_id())
			{
				broker_list->del_cur();
				delete last;
				break;
			}
		}

		broker_list->add_item(std::move(broker));
	}

	return 0;
}

static bool kafka_broker_get_leader(int leader_id, KafkaBrokerList *broker_list,
									kafka_broker_t *leader)
{
	KafkaBroker *bbroker;

	broker_list->rewind();
	while ((bbroker = broker_list->get_next()) != NULL)
	{
		if (bbroker->get_node_id() == leader_id)
		{
			kafka_broker_t *broker = bbroker->get_raw_ptr();

			char *host = strdup(broker->host);
			if (host)
			{
				char *rack = NULL;

				if (broker->rack)
					rack = strdup(broker->rack);

				if (!broker->rack || rack)
				{
					kafka_broker_deinit(leader);
					*leader = *broker;
					leader->host = host;
					leader->rack = rack;
					return true;
				}

				free(host);
			}

			return false;
		}
	}

	errno = EBADMSG;
	return false;
}

static int kafka_meta_parse_partition(void **buf, size_t *size,
									  KafkaMeta *meta,
									  KafkaBrokerList *broker_list)
{
	int32_t leader_id;
	int32_t replica_cnt, isr_cnt;
	int32_t partition_cnt;
	int32_t i, j;

	CHECK_RET(parse_i32(buf, size, &partition_cnt));

	if (partition_cnt < 0)
	{
		errno = EBADMSG;
		return -1;
	}

	if (!meta->create_partitions(partition_cnt))
		return -1;

	kafka_partition_t **partition = meta->get_partitions();

	for (i = 0; i < partition_cnt; ++i)
	{
		int16_t error;
		int32_t index;

		if (parse_i16(buf, size, &error) < 0)
			break;

		partition[i]->error = error;

		if (parse_i32(buf, size, &index) < 0)
			break;

		partition[i]->partition_index = index;

		if (parse_i32(buf, size, &leader_id) < 0)
			break;

		if (!kafka_broker_get_leader(leader_id, broker_list, &partition[i]->leader))
			break;

		if (parse_i32(buf, size, &replica_cnt) < 0)
			break;

		if (!meta->create_replica_nodes(i, replica_cnt))
			break;

		for (j = 0; j < replica_cnt; ++j)
		{
			int32_t replica_node;

			if (parse_i32(buf, size, &replica_node) < 0)
				break;

			partition[i]->replica_nodes[j] = replica_node;
		}

		if (j != replica_cnt)
			break;

		if (parse_i32(buf, size, &isr_cnt) < 0)
			break;

		if (!meta->create_isr_nodes(i, isr_cnt))
			break;

		for (j = 0; j < isr_cnt; ++j)
		{
			int32_t isr_node;

			if (parse_i32(buf, size, &isr_node) < 0)
				break;

			partition[i]->isr_nodes[j] = isr_node;
		}

		if (j != isr_cnt)
			break;
	}

	if (i != partition_cnt)
		return -1;

	return 0;
}

static KafkaMeta *find_meta_by_name(const std::string& topic, KafkaMetaList *meta_list)
{
	meta_list->rewind();
	KafkaMeta *meta;

	while ((meta = meta_list->get_next()) != NULL)
	{
		if (meta->get_topic() == topic)
			return meta;
	}

	errno = EBADMSG;
	return NULL;
}

static int kafka_meta_parse_topic(void **buf, size_t *size,
								  int api_version,
								  KafkaMetaList *meta_list,
								  KafkaBrokerList *broker_list)
{
	KafkaMetaList lst;
	int32_t topic_cnt;

	CHECK_RET(parse_i32(buf, size, &topic_cnt));
	for (int32_t topic_idx = 0; topic_idx < topic_cnt; ++topic_idx)
	{
		int16_t error;
		CHECK_RET(parse_i16(buf, size, &error));

		std::string topic_name;
		CHECK_RET(parse_string(buf, size, topic_name));
		KafkaMeta *meta = find_meta_by_name(topic_name, meta_list);
		if (!meta)
			return -1;

		KafkaMeta new_mta;
		new_mta.set_topic(topic_name);

		kafka_meta_t *ptr = new_mta.get_raw_ptr();
		ptr->error = error;

		if (api_version >= 1)
			CHECK_RET(parse_i8(buf, size, &ptr->is_internal));

		CHECK_RET(kafka_meta_parse_partition(buf, size, &new_mta, broker_list));

		lst.add_item(std::move(new_mta));
	}

	*meta_list = std::move(lst);
	return 0;
}

int KafkaResponse::parse_metadata(void **buf, size_t *size)
{
	int32_t throttle_time, controller_id;
	std::string cluster_id;

	if (this->api_version >= 3)
		CHECK_RET(parse_i32(buf, size, &throttle_time));

	CHECK_RET(kafka_meta_parse_broker(buf, size, this->api_version,
									  &this->broker_list));

	if (this->api_version >= 2)
		CHECK_RET(parse_string(buf, size, cluster_id));

	if (this->api_version >= 1)
		CHECK_RET(parse_i32(buf, size, &controller_id));

	CHECK_RET(kafka_meta_parse_topic(buf, size, this->api_version,
									 &this->meta_list, &this->broker_list));

	return 0;
}

KafkaToppar *KafkaMessage::find_toppar_by_name(const std::string& topic, int partition,
											   struct list_head *toppar_list)
{
	KafkaToppar *toppar;
	struct list_head *pos;

	list_for_each(pos, toppar_list)
	{
		toppar = list_entry(pos, KafkaToppar, list);
		if (toppar->get_topic() == topic && toppar->get_partition() == partition)
			return toppar;
	}

	errno = EBADMSG;
	return NULL;
}

KafkaToppar *KafkaMessage::find_toppar_by_name(const std::string& topic, int partition,
											   KafkaTopparList *toppar_list)
{
	toppar_list->rewind();
	KafkaToppar *toppar;

	while ((toppar = toppar_list->get_next()) != NULL)
	{
		if (toppar->get_topic() == topic &&
			toppar->get_partition() == partition)
			return toppar;
	}

	errno = EBADMSG;
	return NULL;
}

int KafkaResponse::parse_produce(void **buf, size_t *size)
{
	int32_t topic_cnt;
	std::string topic_name;
	int32_t partition_cnt;
	int32_t partition;
	int64_t base_offset, log_append_time, log_start_offset;
	int32_t throttle_time;
	int produce_timeout = this->config.get_produce_timeout() * 2;

	CHECK_RET(parse_i32(buf, size, &topic_cnt));
	for (int32_t topic_idx = 0; topic_idx < topic_cnt; ++topic_idx)
	{
		CHECK_RET(parse_string(buf, size, topic_name));

		CHECK_RET(parse_i32(buf, size, &partition_cnt));
		for (int32_t i = 0; i < partition_cnt; ++i)
		{
			CHECK_RET(parse_i32(buf, size, &partition));

			KafkaToppar *toppar = find_toppar_by_name(topic_name, partition,
													  &this->toppar_list);
			if (!toppar)
				return -1;

			kafka_topic_partition_t *ptr = toppar->get_raw_ptr();

			CHECK_RET(parse_i16(buf, size, &ptr->error));

			log_append_time = -1;
			CHECK_RET(parse_i64(buf, size, &base_offset));

			if (this->api_version >= 2)
				CHECK_RET(parse_i64(buf, size, &log_append_time));

			if (this->api_version >=5)
				CHECK_RET(parse_i64(buf, size, &log_start_offset));

			struct list_head *pos;
			KafkaRecord *record;

			if (ptr->error == KAFKA_REQUEST_TIMED_OUT)
			{
				toppar->restore_record_curpos();
				this->config.set_produce_timeout(produce_timeout);
				continue;
			}

			for (pos = toppar->get_record_startpos()->next;
				 pos != toppar->get_record_endpos(); pos = pos->next)
			{
				record = list_entry(pos, KafkaRecord, list);
				record->set_status(ptr->error);

				if (ptr->error)
					continue;

				record->set_offset(base_offset++);

				if (log_append_time != -1)
					record->set_timestamp(log_append_time);
			}
		}

	}

	if (this->api_version >= 1)
		CHECK_RET(parse_i32(buf, size, &throttle_time));

	return 0;
}

int KafkaResponse::parse_fetch(void **buf, size_t *size)
{
	int32_t throttle_time;

	this->toppar_list.rewind();
	KafkaToppar *toppar;
	while ((toppar = this->toppar_list.get_next()) != NULL)
		toppar->clear_records();

	if (this->api_version >= 1)
		CHECK_RET(parse_i32(buf, size, &throttle_time));

	if (this->api_version >= 7)
	{
		int16_t error;
		int32_t sessionid;
		parse_i16(buf, size, &error);
		parse_i32(buf, size, &sessionid);
	}

	int32_t topic_cnt;
	std::string topic_name;
	int32_t partition_cnt;
	int32_t partition;
	int32_t aborted_cnt;
	int32_t preferred_read_replica;
	int64_t producer_id, first_offset;
	int64_t high_watermark;

	CHECK_RET(parse_i32(buf, size, &topic_cnt));
	for (int32_t topic_idx = 0; topic_idx < topic_cnt; ++topic_idx)
	{
		CHECK_RET(parse_string(buf, size, topic_name));
		CHECK_RET(parse_i32(buf, size, &partition_cnt));

		for (int i = 0; i < partition_cnt; ++i)
		{
			CHECK_RET(parse_i32(buf, size, &partition));

			KafkaToppar *toppar = find_toppar_by_name(topic_name, partition,
													  &this->toppar_list);

			if (!toppar)
				return -1;

			kafka_topic_partition_t *ptr = toppar->get_raw_ptr();

			CHECK_RET(parse_i16(buf, size, &ptr->error));
			CHECK_RET(parse_i64(buf, size, &high_watermark));

			if (high_watermark > ptr->low_watermark)
				ptr->high_watermark = high_watermark;

			if (this->api_version >= 4)
			{
				CHECK_RET(parse_i64(buf, size, (int64_t *)&ptr->last_stable_offset));

				if (this->api_version >= 5)
					CHECK_RET(parse_i64(buf, size, (int64_t *)&ptr->log_start_offset));

				CHECK_RET(parse_i32(buf, size, &aborted_cnt));
				for (int32_t j = 0; j < aborted_cnt; ++j)
				{
					CHECK_RET(parse_i64(buf, size, &producer_id));
					CHECK_RET(parse_i64(buf, size, &first_offset));
				}
			}

			if (this->api_version >= 11)
			{
				CHECK_RET(parse_i32(buf, size, &preferred_read_replica));
				ptr->preferred_read_replica = preferred_read_replica;
			}

			if (parse_records(buf, size, this->config.get_check_crcs(),
							  &this->uncompressed, toppar) != 0)
			{
				ptr->error = KAFKA_CORRUPT_MESSAGE;
				return -1;
			}
		}
	}

	return 0;
}

int KafkaResponse::parse_listoffset(void **buf, size_t *size)
{
	int32_t throttle_time;
	int32_t topic_cnt;
	std::string topic_name;
	int32_t partition_cnt;
	int32_t partition;
	int64_t offset_timestamp, offset;
	int32_t offset_cnt;

	if (this->api_version >= 2)
		CHECK_RET(parse_i32(buf, size, &throttle_time));

	CHECK_RET(parse_i32(buf, size, &topic_cnt));
	for (int32_t topic_idx = 0; topic_idx < topic_cnt; ++topic_idx)
	{
		CHECK_RET(parse_string(buf, size, topic_name));
		CHECK_RET(parse_i32(buf, size, &partition_cnt));

		for (int32_t i = 0; i < partition_cnt; ++i)
		{
			CHECK_RET(parse_i32(buf, size, &partition));

			KafkaToppar *toppar = find_toppar_by_name(topic_name, partition,
													  &this->toppar_list);
			if (!toppar)
				return -1;

			kafka_topic_partition_t *ptr = toppar->get_raw_ptr();

			CHECK_RET(parse_i16(buf, size, &ptr->error));

			if (this->api_version == 1)
			{
				CHECK_RET(parse_i64(buf, size, &offset_timestamp));
				CHECK_RET(parse_i64(buf, size, &offset));
				if (ptr->offset_timestamp == -1)
					ptr->high_watermark = offset;
				else if (ptr->offset_timestamp == -2)
					ptr->low_watermark = offset;
				else
					ptr->offset = offset;
			}
			else if (this->api_version == 0)
			{
				CHECK_RET(parse_i32(buf, size, &offset_cnt));
				for (int32_t j = 0; j < offset_cnt; ++j)
				{
					CHECK_RET(parse_i64(buf, size, &offset));
					ptr->offset = offset;
				}

				ptr->low_watermark = 0;
			}
		}
	}

	return 0;
}

int KafkaResponse::parse_findcoordinator(void **buf, size_t *size)
{
	int32_t throttle_time;

	if (this->api_version >= 1)
		CHECK_RET(parse_i32(buf, size, &throttle_time));

	kafka_cgroup_t *cgroup = this->cgroup.get_raw_ptr();
	CHECK_RET(parse_i16(buf, size, &cgroup->error));

	if (this->api_version >= 1)
		CHECK_RET(parse_string(buf, size, &cgroup->error_msg));

	CHECK_RET(parse_i32(buf, size, &cgroup->coordinator.node_id));
	CHECK_RET(parse_string(buf, size, &cgroup->coordinator.host));
	CHECK_RET(parse_i32(buf, size, &cgroup->coordinator.port));

	return 0;
}

static bool kafka_meta_find_or_add_topic(const std::string& topic_name,
										 KafkaMetaList *meta_list)
{
	meta_list->rewind();
	bool find = false;
	KafkaMeta *meta;

	while ((meta = meta_list->get_next()) != NULL)
	{
		if (topic_name == meta->get_topic())
		{
			find = true;
			break;
		}
	}

	if (!find)
	{
		KafkaMeta tmp;
		if (!tmp.set_topic(topic_name))
			return false;

		meta_list->add_item(tmp);
	}

	return true;
}

static int kafka_cgroup_parse_member(void **buf, size_t *size,
									 KafkaCgroup *cgroup,
									 KafkaMetaList *meta_list,
									 int api_version)
{
	int32_t member_cnt = 0;
	CHECK_RET(parse_i32(buf, size, &member_cnt));

	if (member_cnt < 0)
	{
		errno = EBADMSG;
		return -1;
	}

	if (!cgroup->create_members(member_cnt))
		return -1;

	kafka_member_t **member = cgroup->get_members();
	int32_t i;

	for (i = 0; i < member_cnt; ++i)
	{
		if (parse_string(buf, size, &member[i]->member_id) < 0)
			break;

		if (api_version >= 5)
		{
			std::string group_instance_id;
			parse_string(buf, size, group_instance_id);
		}

		if (parse_bytes(buf, size, &member[i]->member_metadata,
						&member[i]->member_metadata_len) < 0)
			break;

		void *metadata = member[i]->member_metadata;
		size_t metadata_len = member[i]->member_metadata_len;
		int16_t version;
		int32_t topic_cnt;
		std::string topic_name;
		int32_t j;

		if (parse_i16(&metadata, &metadata_len, &version) < 0)
			break;

		if (parse_i32(&metadata, &metadata_len, &topic_cnt) < 0)
			break;

		for (j = 0; j < topic_cnt; ++j)
		{
			if (parse_string(&metadata, &metadata_len, topic_name) < 0)
				break;

			KafkaToppar * toppar = new KafkaToppar;
			if (!toppar->set_topic(topic_name.c_str()))
			{
				delete toppar;
				break;
			}

			list_add_tail(toppar->get_list(), &member[i]->toppar_list);

			if (!kafka_meta_find_or_add_topic(topic_name, meta_list))
				return -1;
		}

		if (j != topic_cnt)
			break;
	}

	if (i != member_cnt)
		return -1;

	return 0;
}

int KafkaResponse::parse_joingroup(void **buf, size_t *size)
{
	int32_t throttle_time;

	if (this->api_version >= 2)
		CHECK_RET(parse_i32(buf, size, &throttle_time));

	kafka_cgroup_t *cgroup = this->cgroup.get_raw_ptr();
	CHECK_RET(parse_i16(buf, size, &cgroup->error));
	CHECK_RET(parse_i32(buf, size, &cgroup->generation_id));

	CHECK_RET(parse_string(buf, size, &cgroup->protocol_name));
	CHECK_RET(parse_string(buf, size, &cgroup->leader_id));
	CHECK_RET(parse_string(buf, size, &cgroup->member_id));
	CHECK_RET(kafka_cgroup_parse_member(buf, size, &this->cgroup,
										&this->meta_list,
										this->api_version));

	return 0;
}

int KafkaMessage::kafka_parse_member_assignment(const char *bbuf, size_t n,
												KafkaCgroup *cgroup)
{
	void **buf = (void **)&bbuf;
	size_t *size = &n;
	int32_t topic_cnt;
	int32_t partition_cnt;
	int16_t version;
	struct list_head *pos, *tmp;
	std::string topic_name;
	int32_t partition;

	list_for_each_safe(pos, tmp, cgroup->get_assigned_toppar_list())
	{
		KafkaToppar *toppar = list_entry(pos, KafkaToppar, list);
		list_del(pos);
		delete toppar;
	}

	CHECK_RET(parse_i16(buf, size, &version));
	CHECK_RET(parse_i32(buf, size, &topic_cnt));
	for (int32_t i = 0; i < topic_cnt; ++i)
	{
		CHECK_RET(parse_string(buf, size, topic_name));
		CHECK_RET(parse_i32(buf, size, &partition_cnt));

		for (int32_t j = 0; j < partition_cnt; ++j)
		{
			CHECK_RET(parse_i32(buf, size, &partition));
			KafkaToppar *toppar = new KafkaToppar;

			if (!toppar->set_topic_partition(topic_name, partition))
			{
				delete toppar;
				return -1;
			}
			cgroup->add_assigned_toppar(toppar);
		}
	}

	return 0;
}

int KafkaResponse::parse_syncgroup(void **buf, size_t *size)
{
	int32_t throttle_time;
	int16_t error;
	std::string member_assignment;

	if (this->api_version >= 1)
		CHECK_RET(parse_i32(buf, size, &throttle_time));

	CHECK_RET(parse_i16(buf, size, &error));
	this->cgroup.set_error(error);

	CHECK_RET(parse_bytes(buf, size, member_assignment));
	if (!member_assignment.empty())
	{
		CHECK_RET(kafka_parse_member_assignment(member_assignment.c_str(),
												member_assignment.size(),
												&this->cgroup));
	}

	return 0;
}

int KafkaResponse::parse_leavegroup(void **buf, size_t *size)
{
	int32_t throttle_time;
	int16_t error;

	if (this->api_version >= 1)
		CHECK_RET(parse_i32(buf, size, &throttle_time));

	CHECK_RET(parse_i16(buf, size, &error));
	this->cgroup.set_error(error);

	return 0;
}

int KafkaResponse::parse_offsetfetch(void **buf, size_t *size)
{
	int32_t topic_cnt;
	std::string topic_name;
	int32_t partition_cnt;
	int32_t partition;

	CHECK_RET(parse_i32(buf, size, &topic_cnt));
	for (int32_t topic_idx = 0; topic_idx < topic_cnt; ++topic_idx)
	{
		CHECK_RET(parse_string(buf, size, topic_name));

		CHECK_RET(parse_i32(buf, size, &partition_cnt));
		for (int32_t i = 0; i < partition_cnt; ++i)
		{
			CHECK_RET(parse_i32(buf, size, &partition));
			KafkaToppar *toppar = find_toppar_by_name(topic_name, partition,
													  this->cgroup.get_assigned_toppar_list());
			if (!toppar)
				return -1;

			kafka_topic_partition_t *ptr = toppar->get_raw_ptr();

			int64_t offset;
			CHECK_RET(parse_i64(buf, size, &offset));
			if (this->config.get_offset_store() != KAFKA_OFFSET_ASSIGN)
				ptr->offset = offset;

			CHECK_RET(parse_string(buf, size, &ptr->committed_metadata));
			CHECK_RET(parse_i16(buf, size, &ptr->error));
		}
	}

	return 0;
}

int KafkaResponse::parse_offsetcommit(void **buf, size_t *size)
{
	int32_t throttle_time;
	int32_t topic_cnt;
	std::string topic_name;
	int32_t partition_cnt;
	int32_t partition;

	if (this->api_version >= 3)
		CHECK_RET(parse_i32(buf, size, &throttle_time));

	CHECK_RET(parse_i32(buf, size, &topic_cnt));
	for (int32_t topic_idx = 0; topic_idx < topic_cnt; ++topic_idx)
	{
		CHECK_RET(parse_string(buf, size, topic_name));
		CHECK_RET(parse_i32(buf, size, &partition_cnt));

		for (int32_t i = 0 ; i < partition_cnt; ++i)
		{
			CHECK_RET(parse_i32(buf, size, &partition));
			CHECK_RET(parse_i16(buf, size, &this->cgroup.get_raw_ptr()->error));
		}
	}

	return 0;
}

int KafkaResponse::parse_heartbeat(void **buf, size_t *size)
{
	int32_t throttle_time;
	int16_t error;

	if (this->api_version >= 1)
		CHECK_RET(parse_i32(buf, size, &throttle_time));

	CHECK_RET(parse_i16(buf, size, &error));

	this->cgroup.set_error(error);
	return 0;
}

static bool kafka_api_version_cmp(const kafka_api_version_t& api_ver1,
								  const kafka_api_version_t& api_ver2)
{
	return api_ver1.api_key < api_ver2.api_key;
}

int KafkaResponse::parse_apiversions(void **buf, size_t *size)
{
	int16_t error;
	int32_t api_cnt;
	int32_t throttle_time;

	CHECK_RET(parse_i16(buf, size, &error));
	CHECK_RET(parse_i32(buf, size, &api_cnt));
	if (api_cnt < 0)
	{
		errno = EBADMSG;
		return -1;
	}

	void *p = malloc(api_cnt * sizeof(kafka_api_version_t));
	if (!p)
		return -1;

	this->api->api = (kafka_api_version_t *)p;
	this->api->elements = api_cnt;

	for (int32_t i = 0; i < api_cnt; ++i)
	{
		CHECK_RET(parse_i16(buf, size, &this->api->api[i].api_key));
		CHECK_RET(parse_i16(buf, size, &this->api->api[i].min_ver));
		CHECK_RET(parse_i16(buf, size, &this->api->api[i].max_ver));
	}

	if (this->api_version >= 1)
		CHECK_RET(parse_i32(buf, size, &throttle_time));

	std::sort(this->api->api, this->api->api + api_cnt, kafka_api_version_cmp);
	this->api->features = kafka_get_features(this->api->api, api_cnt);
	return 0;
}

int KafkaResponse::parse_saslhandshake(void **buf, size_t *size)
{
	std::string mechanism;
	int16_t error = 0;
	int32_t cnt, i;

	CHECK_RET(parse_i16(buf, size, &error));
	if (error != 0)
	{
		this->broker.get_raw_ptr()->error = error;
		return 1;
	}

	CHECK_RET(parse_i32(buf, size, &cnt));

	for (i = 0; i < cnt; i++)
	{
		CHECK_RET(parse_string(buf, size, mechanism));

		if (strcasecmp(mechanism.c_str(), this->config.get_sasl_mech()) == 0)
			break;
	}

	if (i == cnt)
	{
		this->broker.get_raw_ptr()->error = KAFKA_SASL_AUTHENTICATION_FAILED;
		return 1;
	}

	for (i++; i < cnt; i++)
		CHECK_RET(parse_string(buf, size, mechanism));

	errno = 0;
	if (!this->config.new_client(this->sasl))
	{
		if (errno)
			return -1;

		this->broker.get_raw_ptr()->error = KAFKA_SASL_AUTHENTICATION_FAILED;
		return 1;
	}

	return 0;
}

int KafkaResponse::parse_saslauthenticate(void **buf, size_t *size)
{
	std::string error_message;
	std::string auth_bytes;
	int16_t error = 0;

	CHECK_RET(parse_i16(buf, size, &error));
	CHECK_RET(parse_string(buf, size, error_message));
	CHECK_RET(parse_bytes(buf, size, auth_bytes));

	if (error != 0)
	{
		this->broker.get_raw_ptr()->error = error;
		return 1;
	}

	errno = 0;
	if (this->config.get_raw_ptr()->recv(auth_bytes.c_str(),
										 auth_bytes.size(),
										 this->config.get_raw_ptr(),
										 this->sasl) != 0)
	{
		if (errno)
			return -1;

		this->broker.get_raw_ptr()->error = KAFKA_SASL_AUTHENTICATION_FAILED;
		return 1;
	}

	return 0;
}

int KafkaResponse::handle_sasl_continue()
{
	struct iovec iovecs[64];
	int ret;
	int cnt = this->encode(iovecs, 64);
	if ((unsigned int)cnt > 64)
	{
		if (cnt > 64)
			errno = EOVERFLOW;
		return -1;
	}

	for (int i = 0; i < cnt; i++)
	{
		ret = this->feedback(iovecs[i].iov_base, iovecs[i].iov_len);
		if (ret != (int)iovecs[i].iov_len)
		{
			if (ret >= 0)
				errno = ENOBUFS;
			return -1;
		}
	}

	return 0;
}

int KafkaResponse::append(const void *buf, size_t *size)
{
	int ret = KafkaMessage::append(buf, size);

	if (ret <= 0)
		return ret;

	ret = this->parse_response();
	if (ret != 0)
		return ret;

	if (this->api_type == Kafka_SaslHandshake)
	{
		this->api_type = Kafka_SaslAuthenticate;
		this->clear_buf();
		return this->handle_sasl_continue();
	}
	else if (this->api_type == Kafka_SaslAuthenticate)
	{
		if (strncasecmp(this->config.get_sasl_mech(), "SCRAM", 5) == 0)
		{
			this->clear_buf();
			if (this->sasl->scram.state !=
					KAFKA_SASL_SCRAM_STATE_CLIENT_FINISHED)
				return this->handle_sasl_continue();
			else
				this->sasl->status = 1;
		}
	}

	return 1;
}

}


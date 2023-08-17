/*
  Copyright (c) 2019 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Xie Han (xiehan@sogou-inc.com)
*/

#ifndef _MYSQL_STREAM_H_
#define _MYSQL_STREAM_H_

#include <stdlib.h>

typedef struct __mysql_stream
{
	unsigned char head[4];
	unsigned char head_left;
	unsigned char sequence_id;  
	int payload_length;
	int payload_left;
	void *buf;
	size_t length;
	size_t bufsize;
	int (*write)(const void *, size_t *, struct __mysql_stream *);
} mysql_stream_t;

#ifdef __cplusplus
extern "C"
{
#endif

void mysql_stream_init(mysql_stream_t *stream);

#ifdef __cplusplus
}
#endif

static inline int mysql_stream_write(const void *buf, size_t *n,
									 mysql_stream_t *stream)
{
	return stream->write(buf, n, stream);
}

static inline int mysql_stream_get_seq(mysql_stream_t *stream)
{
	return stream->sequence_id;
}

static inline void mysql_stream_get_buf(const void **buf, size_t *length,
										mysql_stream_t *stream)
{
	*buf = stream->buf;
	*length = stream->length;
}

static inline void mysql_stream_deinit(mysql_stream_t *stream)
{
	free(stream->buf);
}

#endif


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

#include <stdlib.h>
#include <string.h>
#include "mysql_stream.h"

#define MAX(x, y)	((x) >= (y) ? (x) : (y))

static int __mysql_stream_write_payload(const void *buf, size_t *n,
										mysql_stream_t *stream);

static int __mysql_stream_write_head(const void *buf, size_t *n,
									  mysql_stream_t *stream)
{
	void *p = &stream->head[4 - stream->head_left];

	if (*n < stream->head_left)
	{
		memcpy(p, buf, *n);
		stream->head_left -= *n;
		return 0;
	}

	memcpy(p, buf, stream->head_left);
	stream->payload_length = (stream->head[2] << 16) +
							 (stream->head[1] << 8) +
							  stream->head[0];
	stream->payload_left = stream->payload_length;
	stream->sequence_id = stream->head[3];
	if (stream->bufsize < stream->length + stream->payload_left)
	{
		size_t new_size = MAX(2048, 2 * stream->bufsize);
		void *new_base;

		while (new_size < stream->length + stream->payload_left)
			new_size *= 2;

		new_base = realloc(stream->buf, new_size);
		if (!new_base)
			return -1;

		stream->buf = new_base;
		stream->bufsize = new_size;
	}

	*n = stream->head_left;
	stream->write = __mysql_stream_write_payload;
	return 0;
}

static int __mysql_stream_write_payload(const void *buf, size_t *n,
										mysql_stream_t *stream)
{
	char *p = (char *)stream->buf + stream->length;

	if (*n < stream->payload_left)
	{
		memcpy(p, buf, *n);
		stream->length += *n;
		stream->payload_left -= *n;
		return 0;
	}

	memcpy(p, buf, stream->payload_left);
	stream->length += stream->payload_left;

	*n = stream->payload_left;
	stream->head_left = 4;
	stream->write = __mysql_stream_write_head;
	return stream->payload_length != (1 << 24) - 1;
}

void mysql_stream_init(mysql_stream_t *stream)
{
	stream->head_left = 4;
	stream->sequence_id = 0;
	stream->buf = NULL;
	stream->length = 0;
	stream->bufsize = 0;
	stream->write = __mysql_stream_write_head;
}


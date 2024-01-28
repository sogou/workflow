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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <utility>
#include "HttpMessage.h"

namespace protocol
{

struct HttpMessageBlock
{
	struct list_head list;
	const void *ptr;
	size_t size;
};

bool HttpMessage::append_output_body(const void *buf, size_t size)
{
	size_t n = sizeof (struct HttpMessageBlock) + size;
	struct HttpMessageBlock *block = (struct HttpMessageBlock *)malloc(n);

	if (block)
	{
		memcpy(block + 1, buf, size);
		block->ptr = block + 1;
		block->size = size;
		list_add_tail(&block->list, &this->output_body);
		this->output_body_size += size;
		return true;
	}

	return false;
}

bool HttpMessage::append_output_body_nocopy(const void *buf, size_t size)
{
	size_t n = sizeof (struct HttpMessageBlock);
	struct HttpMessageBlock *block = (struct HttpMessageBlock *)malloc(n);

	if (block)
	{
		block->ptr = buf;
		block->size = size;
		list_add_tail(&block->list, &this->output_body);
		this->output_body_size += size;
		return true;
	}

	return false;
}

size_t HttpMessage::get_output_body_blocks(const void *buf[], size_t size[],
										   size_t max) const
{
	struct HttpMessageBlock *block;
	struct list_head *pos;
	size_t n = 0;

	list_for_each(pos, &this->output_body)
	{
		if (n == max)
			break;

		block = list_entry(pos, struct HttpMessageBlock, list);
		buf[n] = block->ptr;
		size[n] = block->size;
		n++;
	}

	return n;
}

bool HttpMessage::get_output_body_merged(void *buf, size_t *size) const
{
	struct HttpMessageBlock *block;
	struct list_head *pos;

	if (*size < this->output_body_size)
	{
		errno = ENOSPC;
		return false;
	}

	list_for_each(pos, &this->output_body)
	{
		block = list_entry(pos, struct HttpMessageBlock, list);
		memcpy(buf, block->ptr, block->size);
		buf = (char *)buf + block->size;
	}

	*size = this->output_body_size;
	return true;
}

void HttpMessage::clear_output_body()
{
	struct HttpMessageBlock *block;
	struct list_head *pos, *tmp;

	list_for_each_safe(pos, tmp, &this->output_body)
	{
		block = list_entry(pos, struct HttpMessageBlock, list);
		list_del(pos);
		free(block);
	}

	this->output_body_size = 0;
}

struct list_head *HttpMessage::combine_from(struct list_head *pos, size_t size)
{
	size_t n = sizeof (struct HttpMessageBlock) + size;
	struct HttpMessageBlock *block = (struct HttpMessageBlock *)malloc(n);
	struct HttpMessageBlock *entry;
	char *ptr;

	if (block)
	{
		block->ptr = block + 1;
		block->size = size;
		ptr = (char *)block->ptr;

		do
		{
			entry = list_entry(pos, struct HttpMessageBlock, list);
			pos = pos->next;
			list_del(&entry->list);
			memcpy(ptr, entry->ptr, entry->size);
			ptr += entry->size;
			free(entry);
		} while (pos != &this->output_body);

		list_add_tail(&block->list, &this->output_body);
		return &block->list;
	}

	return NULL;
}

int HttpMessage::encode(struct iovec vectors[], int max)
{
	const char *start_line[3];
	http_header_cursor_t cursor;
	struct HttpMessageHeader header;
	struct HttpMessageBlock *block;
	struct list_head *pos;
	size_t size;
	int i;

	start_line[0] = http_parser_get_method(this->parser);
	if (start_line[0])
	{
		start_line[1] = http_parser_get_uri(this->parser);
		start_line[2] = http_parser_get_version(this->parser);
	}
	else
	{
		start_line[0] = http_parser_get_version(this->parser);
		start_line[1] = http_parser_get_code(this->parser);
		start_line[2] = http_parser_get_phrase(this->parser);
	}

	if (!start_line[0] || !start_line[1] || !start_line[2])
	{
		errno = EBADMSG;
		return -1;
	}

	vectors[0].iov_base = (void *)start_line[0];
	vectors[0].iov_len = strlen(start_line[0]);
	vectors[1].iov_base = (void *)" ";
	vectors[1].iov_len = 1;

	vectors[2].iov_base = (void *)start_line[1];
	vectors[2].iov_len = strlen(start_line[1]);
	vectors[3].iov_base = (void *)" ";
	vectors[3].iov_len = 1;

	vectors[4].iov_base = (void *)start_line[2];
	vectors[4].iov_len = strlen(start_line[2]);
	vectors[5].iov_base = (void *)"\r\n";
	vectors[5].iov_len = 2;

	i = 6;
	http_header_cursor_init(&cursor, this->parser);
	while (http_header_cursor_next(&header.name, &header.name_len,
								   &header.value, &header.value_len,
								   &cursor) == 0)
	{
		if (i == max)
			break;

		vectors[i].iov_base = (void *)header.name;
		vectors[i].iov_len = header.name_len + 2 + header.value_len + 2;
		i++;
	}

	http_header_cursor_deinit(&cursor);
	if (i + 1 >= max)
	{
		errno = EOVERFLOW;
		return -1;
	}

	vectors[i].iov_base = (void *)"\r\n";
	vectors[i].iov_len = 2;
	i++;

	size = this->output_body_size;
	list_for_each(pos, &this->output_body)
	{
		if (i + 1 == max && pos != this->output_body.prev)
		{
			pos = this->combine_from(pos, size);
			if (!pos)
				return -1;
		}

		block = list_entry(pos, struct HttpMessageBlock, list);
		vectors[i].iov_base = (void *)block->ptr;
		vectors[i].iov_len = block->size;
		size -= block->size;
		i++;
	}

	return i;
}

inline int HttpMessage::append(const void *buf, size_t *size)
{
	int ret = http_parser_append_message(buf, size, this->parser);

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

HttpMessage::HttpMessage(HttpMessage&& msg) :
	ProtocolMessage(std::move(msg))
{
	this->parser = msg.parser;
	msg.parser = NULL;

	INIT_LIST_HEAD(&this->output_body);
	list_splice_init(&msg.output_body, &this->output_body);
	this->output_body_size = msg.output_body_size;
	msg.output_body_size = 0;

	this->cur_size = msg.cur_size;
	msg.cur_size = 0;
}

HttpMessage& HttpMessage::operator = (HttpMessage&& msg)
{
	if (&msg != this)
	{
		*(ProtocolMessage *)this = std::move(msg);

		if (this->parser)
		{
			http_parser_deinit(this->parser);
			delete this->parser;
		}

		this->parser = msg.parser;
		msg.parser = NULL;

		this->clear_output_body();
		list_splice_init(&msg.output_body, &this->output_body);
		this->output_body_size = msg.output_body_size;
		msg.output_body_size = 0;

		this->cur_size = msg.cur_size;
		msg.cur_size = 0;
	}

	return *this;
}

#define HTTP_100_STATUS_LINE	"HTTP/1.1 100 Continue"
#define HTTP_400_STATUS_LINE	"HTTP/1.1 400 Bad Request"
#define HTTP_413_STATUS_LINE	"HTTP/1.1 413 Request Entity Too Large"
#define HTTP_417_STATUS_LINE	"HTTP/1.1 417 Expectation Failed"
#define CONTENT_LENGTH_ZERO		"Content-Length: 0"
#define CONNECTION_CLOSE		"Connection: close"
#define CRLF					"\r\n"

#define HTTP_100_RESP			HTTP_100_STATUS_LINE CRLF \
								CRLF
#define HTTP_400_RESP			HTTP_400_STATUS_LINE CRLF \
								CONTENT_LENGTH_ZERO CRLF \
								CONNECTION_CLOSE CRLF \
								CRLF
#define HTTP_413_RESP			HTTP_413_STATUS_LINE CRLF \
								CONTENT_LENGTH_ZERO CRLF \
								CONNECTION_CLOSE CRLF \
								CRLF
#define HTTP_417_RESP			HTTP_417_STATUS_LINE CRLF \
								CONTENT_LENGTH_ZERO CRLF \
								CONNECTION_CLOSE CRLF \
								CRLF

int HttpRequest::handle_expect_continue()
{
	size_t trans_len = this->parser->transfer_length;
	int ret;

	if (trans_len != (size_t)-1)
	{
		if (this->parser->header_offset + trans_len > this->size_limit)
		{
			this->feedback(HTTP_417_RESP, strlen(HTTP_417_RESP));
			errno = EMSGSIZE;
			return -1;
		}
	}

	ret = this->feedback(HTTP_100_RESP, strlen(HTTP_100_RESP));
	if (ret != strlen(HTTP_100_RESP))
	{
		if (ret >= 0)
			errno = ENOBUFS;
		return -1;
	}

	return 0;
}

int HttpRequest::append(const void *buf, size_t *size)
{
	int ret = HttpMessage::append(buf, size);

	if (ret == 0)
	{
		if (this->parser->expect_continue &&
			http_parser_header_complete(this->parser))
		{
			this->parser->expect_continue = 0;
			ret = this->handle_expect_continue();
		}
	}
	else if (ret < 0)
	{
		if (errno == EBADMSG)
			this->feedback(HTTP_400_RESP, strlen(HTTP_400_RESP));
		else if (errno == EMSGSIZE)
			this->feedback(HTTP_413_RESP, strlen(HTTP_413_RESP));
	}

	return ret;
}

int HttpResponse::append(const void *buf, size_t *size)
{
	int ret = HttpMessage::append(buf, size);

	if (ret > 0)
	{
		if (strcmp(http_parser_get_code(this->parser), "100") == 0)
		{
			http_parser_deinit(this->parser);
			http_parser_init(1, this->parser);
			ret = 0;
		}
	}

	return ret;
}

}


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
#include "list.h"
#include "http_parser.h"

#define MIN(x, y)	((x) <= (y) ? (x) : (y))
#define MAX(x, y)	((x) >= (y) ? (x) : (y))

#define HTTP_START_LINE_MAX		8192
#define HTTP_HEADER_VALUE_MAX	8192
#define HTTP_CHUNK_LINE_MAX		1024
#define HTTP_TRAILER_LINE_MAX	8192
#define HTTP_MSGBUF_INIT_SIZE	2048

enum
{
	HPS_START_LINE,
	HPS_HEADER_NAME,
	HPS_HEADER_VALUE,
	HPS_HEADER_COMPLETE
};

enum
{
	CPS_CHUNK_DATA,
	CPS_TRAILER_PART,
	CPS_CHUNK_COMPLETE
};

struct __header_line
{
	struct list_head list;
	int name_len;
	int value_len;
	char *buf;
};

static int __add_message_header(const void *name, size_t name_len,
								const void *value, size_t value_len,
								http_parser_t *parser)
{
	size_t size = sizeof (struct __header_line) + name_len + value_len + 4;
	struct __header_line *line;

	line = (struct __header_line *)malloc(size);
	if (line)
	{
		line->buf = (char *)(line + 1);
		memcpy(line->buf, name, name_len);
		line->buf[name_len] = ':';
		line->buf[name_len + 1] = ' ';
		memcpy(line->buf + name_len + 2, value, value_len);
		line->buf[name_len + 2 + value_len] = '\r';
		line->buf[name_len + 2 + value_len + 1] = '\n';
		line->name_len = name_len;
		line->value_len = value_len;
		list_add_tail(&line->list, &parser->header_list);
		return 0;
	}

	return -1;
}

static int __set_message_header(const void *name, size_t name_len,
								const void *value, size_t value_len,
								http_parser_t *parser)
{
	struct __header_line *line;
	struct list_head *pos;
	char *buf;

	list_for_each(pos, &parser->header_list)
	{
		line = list_entry(pos, struct __header_line, list);
		if (line->name_len == name_len &&
			strncasecmp(line->buf, name, name_len) == 0)
		{
			if (value_len > line->value_len)
			{
				buf = (char *)malloc(name_len + value_len + 4);
				if (!buf)
					return -1;

				if (line->buf != (char *)(line + 1))
					free(line->buf);

				line->buf = buf;
				memcpy(buf, name, name_len);
				buf[name_len] = ':';
				buf[name_len + 1] = ' ';
			}

			memcpy(line->buf + name_len + 2, value, value_len);
			line->buf[name_len + 2 + value_len] = '\r';
			line->buf[name_len + 2 + value_len + 1] = '\n';
			line->value_len = value_len;
			return 0;
		}
	}

	return __add_message_header(name, name_len, value, value_len, parser);
}

static int __match_request_line(const char *method,
								const char *uri,
								const char *version,
								http_parser_t *parser)
{
	if (strcmp(version, "HTTP/1.0") == 0 || strncmp(version, "HTTP/0", 6) == 0)
		parser->keep_alive = 0;

	method = strdup(method);
	if (method)
	{
		uri = strdup(uri);
		if (uri)
		{
			version = strdup(version);
			if (version)
			{
				free(parser->method);
				free(parser->uri);
				free(parser->version);
				parser->method = (char *)method;
				parser->uri = (char *)uri;
				parser->version = (char *)version;
				return 0;
			}

			free((char *)uri);
		}

		free((char *)method);
	}

	return -1;
}

static int __match_status_line(const char *version,
							   const char *code,
							   const char *phrase,
							   http_parser_t *parser)
{
	if (strcmp(version, "HTTP/1.0") == 0 || strncmp(version, "HTTP/0", 6) == 0)
		parser->keep_alive = 0;

	if (*code == '1' || strcmp(code, "204") == 0 || strcmp(code, "304") == 0)
		parser->transfer_length = 0;

	version = strdup(version);
	if (version)
	{
		code = strdup(code);
		if (code)
		{
			phrase = strdup(phrase);
			if (phrase)
			{
				free(parser->version);
				free(parser->code);
				free(parser->phrase);
				parser->version = (char *)version;
				parser->code = (char *)code;
				parser->phrase = (char *)phrase;
				return 0;
			}

			free((char *)code);
		}

		free((char *)version);
	}

	return -1;
}

static void __check_message_header(const char *name, size_t name_len,
								   const char *value, size_t value_len,
								   http_parser_t *parser)
{
	switch (name_len)
	{
	case 6:
		if (strncasecmp(name, "Expect", 6) == 0)
		{
			if (value_len == 12 && strncasecmp(value, "100-continue", 12) == 0)
				parser->expect_continue = 1;
		}

		break;

	case 10:
		if (strncasecmp(name, "Connection", 10) == 0)
		{
			parser->has_connection = 1;
			if (value_len == 10 && strncasecmp(value, "Keep-Alive", 10) == 0)
				parser->keep_alive = 1;
			else if (value_len == 5 && strncasecmp(value, "close", 5) == 0)
				parser->keep_alive = 0;
		}
		else if (strncasecmp(name, "Keep-Alive", 10) == 0)
			parser->has_keep_alive = 1;

		break;

	case 14:
		if (strncasecmp(name, "Content-Length", 14) == 0)
		{
			parser->has_content_length = 1;
			if (*value >= '0' && *value <= '9' && value_len <= 15)
			{
				char buf[16];
				memcpy(buf, value, value_len);
				buf[value_len] = '\0';
				parser->content_length = atol(buf);
			}
		}

		break;

	case 17:
		if (strncasecmp(name, "Transfer-Encoding", 17) == 0)
		{
			if (value_len != 8 || strncasecmp(value, "identity", 8) != 0)
				parser->chunked = 1;
			else
				parser->chunked = 0;
		}

		break;
	}
}

static int __parse_start_line(const char *ptr, size_t len,
							  http_parser_t *parser)
{
	char start_line[HTTP_START_LINE_MAX];
	size_t min = MIN(HTTP_START_LINE_MAX, len);
	char *p1, *p2, *p3;
	size_t i;
	int ret;

	if (len >= 2 && ptr[0] == '\r' && ptr[1] == '\n')
	{
		parser->header_offset += 2;
		return 1;
	}

	for (i = 0; i < min; i++)
	{
		start_line[i] = ptr[i];
		if (start_line[i] == '\r')
		{
			if (i == len - 1)
				return 0;

			if (ptr[i + 1] != '\n')
				return -2;

			start_line[i] = '\0';
			p1 = start_line;
			p2 = strchr(p1, ' ');
			if (p2)
				*p2++ = '\0';
			else
				return -2;

			p3 = strchr(p2, ' ');
			if (p3)
				*p3++ = '\0';
			else
				return -2;

			if (parser->is_resp)
				ret = __match_status_line(p1, p2, p3, parser);
			else
				ret = __match_request_line(p1, p2, p3, parser);

			if (ret < 0)
				return -1;

			parser->header_offset += i + 2;
			parser->header_state = HPS_HEADER_NAME;
			return 1;
		}

		if (start_line[i] == 0)
			return -2;
	}

	if (i == HTTP_START_LINE_MAX)
		return -2;

	return 0;
}

static int __parse_header_name(const char *ptr, size_t len,
							   http_parser_t *parser)
{
	size_t min = MIN(HTTP_HEADER_NAME_MAX, len);
	size_t i;

	if (len >= 2 && ptr[0] == '\r' && ptr[1] == '\n')
	{
		parser->header_offset += 2;
		parser->header_state = HPS_HEADER_COMPLETE;
		return 1;
	}

	for (i = 0; i < min; i++)
	{
		if (ptr[i] == ':')
		{
			parser->namebuf[i] = '\0';
			parser->header_offset += i + 1;
			parser->header_state = HPS_HEADER_VALUE;
			return 1;
		}

		if ((signed char)ptr[i] <= 0)
			return -2;

		parser->namebuf[i] = ptr[i];
	}

	if (i == HTTP_HEADER_NAME_MAX)
		return -2;

	return 0;
}

static int __parse_header_value(const char *ptr, size_t len,
								http_parser_t *parser)
{
	char header_value[HTTP_HEADER_VALUE_MAX];
	const char *end = ptr + len;
	const char *begin = ptr;
	size_t i = 0;

	while (1)
	{
		while (1)
		{
			if (ptr == end)
				return 0;

			if (*ptr == ' ' || *ptr == '\t')
				ptr++;
			else
				break;
		}

		while (1)
		{
			if (i == HTTP_HEADER_VALUE_MAX)
				return -2;

			header_value[i] = *ptr++;
			if (ptr == end)
				return 0;

			if (header_value[i] == '\r')
				break;

			if ((signed char)header_value[i] <= 0)
				return -2;

			i++;
		}

		if (*ptr == '\n')
			ptr++;
		else
			return -2;

		if (ptr == end)
			return 0;

		while (i > 0)
		{
			if (header_value[i - 1] == ' ' || header_value[i - 1] == '\t')
				i--;
			else
				break;
		}

		if (*ptr != ' ' && *ptr != '\t')
			break;

		ptr++;
		header_value[i++] = ' ';
	}

	header_value[i] = '\0';
	if (http_parser_add_header(parser->namebuf, strlen(parser->namebuf),
							   header_value, i, parser) < 0)
		return -1;

	parser->header_offset += ptr - begin;
	parser->header_state = HPS_HEADER_NAME;
	return 1;
}

static int __parse_message_header(const void *message, size_t size,
								  http_parser_t *parser)
{
	const char *ptr;
	size_t len;
	int ret;

	do
	{
		ptr = (const char *)message + parser->header_offset;
		len = size - parser->header_offset;
		if (parser->header_state == HPS_START_LINE)
			ret = __parse_start_line(ptr, len, parser);
		else if (parser->header_state == HPS_HEADER_VALUE)
			ret = __parse_header_value(ptr, len, parser);
		else /* if (parser->header_state == HPS_HEADER_NAME) */
		{
			ret = __parse_header_name(ptr, len, parser);
			if (parser->header_state == HPS_HEADER_COMPLETE)
				return 1;
		}
	} while (ret > 0);

	return ret;
}

#define CHUNK_SIZE_MAX		(2 * 1024 * 1024 * 1024U - HTTP_CHUNK_LINE_MAX - 4)

static int __parse_chunk_data(const char *ptr, size_t len,
							  http_parser_t *parser)
{
	char chunk_line[HTTP_CHUNK_LINE_MAX];
	size_t min = MIN(HTTP_CHUNK_LINE_MAX, len);
	long chunk_size;
	char *end;
	size_t i;

	for (i = 0; i < min; i++)
	{
		chunk_line[i] = ptr[i];
		if (chunk_line[i] == '\r')
		{
			if (i == len - 1)
				return 0;

			if (ptr[i + 1] != '\n')
				return -2;

			chunk_line[i] = '\0';
			chunk_size = strtol(chunk_line, &end, 16);
			if (end == chunk_line)
				return -2;

			if (chunk_size == 0)
			{
				chunk_size = i + 2;
				parser->chunk_state = CPS_TRAILER_PART;
			}
			else if ((unsigned long)chunk_size < CHUNK_SIZE_MAX)
			{
				chunk_size += i + 4;
				if (len < (size_t)chunk_size)
					return 0;
			}
			else
				return -2;

			parser->chunk_offset += chunk_size;
			return 1;
		}
	}

	if (i == HTTP_CHUNK_LINE_MAX)
		return -2;

	return 0;
}

static int __parse_trailer_part(const char *ptr, size_t len,
								http_parser_t *parser)
{
	size_t min = MIN(HTTP_TRAILER_LINE_MAX, len);
	size_t i;

	for (i = 0; i < min; i++)
	{
		if (ptr[i] == '\r')
		{
			if (i == len - 1)
				return 0;

			if (ptr[i + 1] != '\n')
				return -2;

			parser->chunk_offset += i + 2;
			if (i == 0)
				parser->chunk_state = CPS_CHUNK_COMPLETE;

			return 1;
		}
	}

	if (i == HTTP_TRAILER_LINE_MAX)
		return -2;

	return 0;
}

static int __parse_chunk(const void *message, size_t size,
						 http_parser_t *parser)
{
	const char *ptr;
	size_t len;
	int ret;

	do
	{
		ptr = (const char *)message + parser->chunk_offset;
		len = size - parser->chunk_offset;
		if (parser->chunk_state == CPS_CHUNK_DATA)
			ret = __parse_chunk_data(ptr, len, parser);
		else /* if (parser->chunk_state == CPS_TRAILER_PART) */
		{
			ret = __parse_trailer_part(ptr, len, parser);
			if (parser->chunk_state == CPS_CHUNK_COMPLETE)
				return 1;
		}
	} while (ret > 0);

	return ret;
}

void http_parser_init(int is_resp, http_parser_t *parser)
{
	parser->header_state = HPS_START_LINE;
	parser->header_offset = 0;
	parser->transfer_length = (size_t)-1;
	parser->content_length = is_resp ? (size_t)-1 : 0;
	parser->version = NULL;
	parser->method = NULL;
	parser->uri = NULL;
	parser->code = NULL;
	parser->phrase = NULL;
	INIT_LIST_HEAD(&parser->header_list);
	parser->msgbuf = NULL;
	parser->msgsize = 0;
	parser->bufsize = 0;
	parser->has_connection = 0;
	parser->has_content_length = 0;
	parser->has_keep_alive = 0;
	parser->expect_continue = 0;
	parser->keep_alive = 1;
	parser->chunked = 0;
	parser->complete = 0;
	parser->is_resp = is_resp;
}

int http_parser_append_message(const void *buf, size_t *n,
							   http_parser_t *parser)
{
	int ret;

	if (parser->complete)
	{
		*n = 0;
		return 1;
	}

	if (parser->msgsize + *n + 1 > parser->bufsize)
	{
		size_t new_size = MAX(HTTP_MSGBUF_INIT_SIZE, 2 * parser->bufsize);
		void *new_base;

		while (new_size < parser->msgsize + *n + 1)
			new_size *= 2;

		new_base = realloc(parser->msgbuf, new_size);
		if (!new_base)
			return -1;

		parser->msgbuf = new_base;
		parser->bufsize = new_size;
	}

	memcpy((char *)parser->msgbuf + parser->msgsize, buf, *n);
	parser->msgsize += *n;
	if (parser->header_state != HPS_HEADER_COMPLETE)
	{
		ret = __parse_message_header(parser->msgbuf, parser->msgsize, parser);
		if (ret <= 0)
			return ret;

		if (parser->chunked)
		{
			parser->chunk_offset = parser->header_offset;
			parser->chunk_state = CPS_CHUNK_DATA;
		}
		else if (parser->transfer_length == (size_t)-1)
			parser->transfer_length = parser->content_length;
	}

	if (parser->transfer_length != (size_t)-1)
	{
		size_t total = parser->header_offset + parser->transfer_length;

		if (parser->msgsize >= total)
		{
			*n -= parser->msgsize - total;
			parser->msgsize = total;
			parser->complete = 1;
			return 1;
		}

		return 0;
	}

	if (!parser->chunked)
		return 0;

	if (parser->chunk_state != CPS_CHUNK_COMPLETE)
	{
		ret = __parse_chunk(parser->msgbuf, parser->msgsize, parser);
		if (ret <= 0)
			return ret;
	}

	*n -= parser->msgsize - parser->chunk_offset;
	parser->msgsize = parser->chunk_offset;
	parser->complete = 1;
	return 1;
}

int http_parser_header_complete(const http_parser_t *parser)
{
	return parser->header_state == HPS_HEADER_COMPLETE;
}

int http_parser_get_body(const void **body, size_t *size,
						 const http_parser_t *parser)
{
	if (parser->complete && parser->header_state == HPS_HEADER_COMPLETE)
	{
		*body = (char *)parser->msgbuf + parser->header_offset;
		*size = parser->msgsize - parser->header_offset;
		((char *)parser->msgbuf)[parser->msgsize] = '\0';
		return 0;
	}

	return 1;
}

int http_parser_set_method(const char *method, http_parser_t *parser)
{
	method = strdup(method);
	if (method)
	{
		free(parser->method);
		parser->method = (char *)method;
		return 0;
	}

	return -1;
}

int http_parser_set_uri(const char *uri, http_parser_t *parser)
{
	uri = strdup(uri);
	if (uri)
	{
		free(parser->uri);
		parser->uri = (char *)uri;
		return 0;
	}

	return -1;
}

int http_parser_set_version(const char *version, http_parser_t *parser)
{
	version = strdup(version);
	if (version)
	{
		free(parser->version);
		parser->version = (char *)version;
		return 0;
	}

	return -1;
}

int http_parser_set_code(const char *code, http_parser_t *parser)
{
	code = strdup(code);
	if (code)
	{
		free(parser->code);
		parser->code = (char *)code;
		return 0;
	}

	return -1;
}

int http_parser_set_phrase(const char *phrase, http_parser_t *parser)
{
	phrase = strdup(phrase);
	if (phrase)
	{
		free(parser->phrase);
		parser->phrase = (char *)phrase;
		return 0;
	}

	return -1;
}

int http_parser_add_header(const void *name, size_t name_len,
						   const void *value, size_t value_len,
						   http_parser_t *parser)
{
	if (__add_message_header(name, name_len, value, value_len, parser) >= 0)
	{
		__check_message_header((const char *)name, name_len,
							   (const char *)value, value_len,
							   parser);
		return 0;
	}

	return -1;
}

int http_parser_set_header(const void *name, size_t name_len,
						   const void *value, size_t value_len,
						   http_parser_t *parser)
{
	if (__set_message_header(name, name_len, value, value_len, parser) >= 0)
	{
		__check_message_header((const char *)name, name_len,
							   (const char *)value, value_len,
							   parser);
		return 0;
	}

	return -1;
}

void http_parser_deinit(http_parser_t *parser)
{
	struct __header_line *line;
	struct list_head *pos, *tmp;

	list_for_each_safe(pos, tmp, &parser->header_list)
	{
		line = list_entry(pos, struct __header_line, list);
		list_del(pos);
		if (line->buf != (char *)(line + 1))
			free(line->buf);

		free(line);
	}

	free(parser->version);
	free(parser->method);
	free(parser->uri);
	free(parser->code);
	free(parser->phrase);
	free(parser->msgbuf);
}

int http_header_cursor_next(const void **name, size_t *name_len,
							const void **value, size_t *value_len,
							http_header_cursor_t *cursor)
{
	struct __header_line *line;

	if (cursor->next->next != cursor->head)
	{
		cursor->next = cursor->next->next;
		line = list_entry(cursor->next, struct __header_line, list);
		*name = line->buf;
		*name_len = line->name_len;
		*value = line->buf + line->name_len + 2;
		*value_len = line->value_len;
		return 0;
	}

	return 1;
}

int http_header_cursor_find(const void *name, size_t name_len,
							const void **value, size_t *value_len,
							http_header_cursor_t *cursor)
{
	struct __header_line *line;

	while (cursor->next->next != cursor->head)
	{
		cursor->next = cursor->next->next;
		line = list_entry(cursor->next, struct __header_line, list);
		if (line->name_len == name_len)
		{
			if (strncasecmp(line->buf, name, name_len) == 0)
			{
				*value = line->buf + name_len + 2;
				*value_len = line->value_len;
				return 0;
			}
		}
	}

	return 1;
}

int http_header_cursor_erase(http_header_cursor_t *cursor)
{
	struct __header_line *line;

	if (cursor->next != cursor->head)
	{
		line = list_entry(cursor->next, struct __header_line, list);
		cursor->next = cursor->next->prev;
		list_del(&line->list);
		if (line->buf != (char *)(line + 1))
			free(line->buf);

		free(line);
		return 0;
	}

	return 1;
}


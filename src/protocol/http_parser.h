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

#ifndef _HTTP_PARSER_H_
#define _HTTP_PARSER_H_

#include <stddef.h>
#include "list.h"

#define HTTP_HEADER_NAME_MAX	64

typedef struct __http_parser
{
	int header_state;
	int chunk_state;
	size_t header_offset;
	size_t chunk_offset;
	size_t content_length;
	size_t transfer_length;
	char *version;
	char *method;
	char *uri;
	char *code;
	char *phrase;
	struct list_head header_list;
	char namebuf[HTTP_HEADER_NAME_MAX];
	void *msgbuf;
	size_t msgsize;
	size_t bufsize;
	char has_connection;
	char has_content_length;
	char has_keep_alive;
	char expect_continue;
	char keep_alive;
	char chunked;
	char complete;
	char is_resp;
} http_parser_t;

typedef struct __http_header_cursor
{
	const struct list_head *head;
	const struct list_head *next;
} http_header_cursor_t;

#ifdef __cplusplus
extern "C"
{
#endif

void http_parser_init(int is_resp, http_parser_t *parser);
int http_parser_append_message(const void *buf, size_t *n,
							   http_parser_t *parser);
int http_parser_get_body(const void **body, size_t *size,
						 const http_parser_t *parser);
int http_parser_header_complete(const http_parser_t *parser);
int http_parser_set_method(const char *method, http_parser_t *parser);
int http_parser_set_uri(const char *uri, http_parser_t *parser);
int http_parser_set_version(const char *version, http_parser_t *parser);
int http_parser_set_code(const char *code, http_parser_t *parser);
int http_parser_set_phrase(const char *phrase, http_parser_t *parser);
int http_parser_add_header(const void *name, size_t name_len,
						   const void *value, size_t value_len,
						   http_parser_t *parser);
int http_parser_set_header(const void *name, size_t name_len,
						   const void *value, size_t value_len,
						   http_parser_t *parser);
void http_parser_deinit(http_parser_t *parser);

int http_header_cursor_next(const void **name, size_t *name_len,
							const void **value, size_t *value_len,
							http_header_cursor_t *cursor);
int http_header_cursor_find(const void *name, size_t name_len,
							const void **value, size_t *value_len,
							http_header_cursor_t *cursor);
int http_header_cursor_erase(http_header_cursor_t *cursor);

#ifdef __cplusplus
}
#endif

static inline const char *http_parser_get_method(const http_parser_t *parser)
{
	return parser->method;
}

static inline const char *http_parser_get_uri(const http_parser_t *parser)
{
	return parser->uri;
}

static inline const char *http_parser_get_version(const http_parser_t *parser)
{
	return parser->version;
}

static inline const char *http_parser_get_code(const http_parser_t *parser)
{
	return parser->code;
}

static inline const char *http_parser_get_phrase(const http_parser_t *parser)
{
	return parser->phrase;
}

static inline int http_parser_chunked(const http_parser_t *parser)
{
	return parser->chunked;
}

static inline int http_parser_keep_alive(const http_parser_t *parser)
{
	return parser->keep_alive;
}

static inline int http_parser_has_connection(const http_parser_t *parser)
{
	return parser->has_connection;
}

static inline int http_parser_has_content_length(const http_parser_t *parser)
{
	return parser->has_content_length;
}

static inline int http_parser_has_keep_alive(const http_parser_t *parser)
{
	return parser->has_keep_alive;
}

static inline void http_parser_close_message(http_parser_t *parser)
{
	parser->complete = 1;
}

static inline void http_header_cursor_init(http_header_cursor_t *cursor,
										   const http_parser_t *parser)
{
	cursor->head = &parser->header_list;
	cursor->next = cursor->head;
}

static inline void http_header_cursor_rewind(http_header_cursor_t *cursor)
{
	cursor->next = cursor->head;
}

static inline void http_header_cursor_deinit(http_header_cursor_t *cursor)
{
}

#endif


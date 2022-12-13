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

  Authors: Wu Jiaxu (wujiaxu@sogou-inc.com)
           Liu Kai (liukaidx@sogou-inc.com)
*/

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "list.h"
#include "redis_parser.h"

#define MIN(x, y)	((x) <= (y) ? (x) : (y))
#define MAX(x, y)	((x) >= (y) ? (x) : (y))

#define REDIS_MSGBUF_INIT_SIZE		8
#define REDIS_REPLY_DEPTH_LIMIT		64
#define REDIS_ARRAY_SIZE_LIMIT		(4 * 1024 * 1024)

enum
{
	//REDIS_PARSE_INIT = 0,
	REDIS_GET_CMD = 1,
	REDIS_GET_CR,
	REDIS_GET_LF,
	REDIS_UNTIL_CRLF,
	REDIS_GET_NCHAR,
	REDIS_PARSE_END
};

struct __redis_read_record
{
	struct list_head list;
	redis_reply_t *reply;
};

void redis_reply_deinit(redis_reply_t *reply)
{
	size_t i;

	for (i = 0; i < reply->elements; i++)
	{
		redis_reply_deinit(reply->element[i]);
		free(reply->element[i]);
	}

	free(reply->element);
}

static redis_reply_t **__redis_create_array(size_t size, redis_reply_t *reply)
{
	size_t elements = 0;
	redis_reply_t **element = (redis_reply_t **)malloc(size * sizeof (void *));

	if (element)
	{
		size_t i;

		for (i = 0; i < size; i++)
		{
			element[i] = (redis_reply_t *)malloc(sizeof (redis_reply_t));
			if (element[i])
			{
				redis_reply_init(element[i]);
				elements++;
				continue;
			}

			break;
		}

		if (elements == size)
			return element;

		while (elements > 0)
			free(element[--elements]);

		free(element);
	}

	return NULL;
}

int redis_reply_set_array(size_t size, redis_reply_t *reply)
{
	redis_reply_t **element = __redis_create_array(size, reply);

	if (element == NULL)
		return -1;

	redis_reply_deinit(reply);
	reply->element = element;
	reply->elements = size;
	reply->type = REDIS_REPLY_TYPE_ARRAY;
	return 0;
}

static int __redis_parse_cmd(const char ch, redis_parser_t *parser)
{
	switch (ch)
	{
	case '+':
	case '-':
	case ':':
	case '$':
	case '*':
		parser->cmd = ch;
		parser->status = REDIS_UNTIL_CRLF;
		parser->findidx = parser->msgidx;
		return 0;
	}

	return -2;
}

static int __redis_parse_cr(const char ch, redis_parser_t *parser)
{
	if (ch != '\r')
		return -2;

	parser->status = REDIS_GET_LF;
	return 0;
}

static int __redis_parse_lf(const char ch, redis_parser_t *parser)
{
	if (ch != '\n')
		return -2;

	return 1;
}

static int __redis_parse_line(redis_parser_t *parser)
{
	char *str = parser->msgbuf + parser->msgidx;
	size_t slen = parser->findidx - parser->msgidx;
	char data[32];
	int i, n;
	const char *offset = (const char *)parser->msgidx;
	struct __redis_read_record *node;

	parser->msgidx = parser->findidx + 2;
	switch (parser->cmd)
	{
	case '+':
		redis_reply_set_status(offset, slen, parser->cur);
		return 1;

	case '-':
		redis_reply_set_error(offset, slen, parser->cur);
		return 1;

	case ':':
		if (slen == 0 || slen > 30)
			return -2;

		memcpy(data, str, slen);
		data[slen] = '\0';
		redis_reply_set_integer(atoll(data), parser->cur);
		return 1;

	case '$':
		n = atoi(str);
		if (n < 0)
		{
			redis_reply_set_null(parser->cur);
			return 1;
		}
		else if (n == 0)
		{
			/* "-0" not acceptable. */
			if (!isdigit(*str))
				return -2;

			redis_reply_set_string(offset, 0, parser->cur);
			parser->status = REDIS_GET_CR;
			return 0;
		}

		parser->nchar = n;
		parser->status = REDIS_GET_NCHAR;
		return 0;

	case '*':
		n = atoi(str);
		if (n < 0)
		{
			redis_reply_set_null(parser->cur);
			return 1;
		}

		if (n == 0 && !isdigit(*str))
			return -2;

		if (n > REDIS_ARRAY_SIZE_LIMIT)
			return -2;

		parser->nleft += n;
		if (redis_reply_set_array(n, parser->cur) < 0)
			return -1;

		if (n == 0)
			return 1;

		parser->nleft--;
		for (i = 0; i < n - 1; i++)
		{
			node = (struct __redis_read_record *)malloc(sizeof *node);
			if (!node)
				return -1;

			node->reply = parser->cur->element[n - 1 - i];
			list_add(&node->list, &parser->read_list);
		}

		parser->cur = parser->cur->element[0];
		parser->status = REDIS_GET_CMD;
		return 0;

	}

	return -2;
}

static int __redis_parse_crlf(redis_parser_t *parser)
{
	char *buf = parser->msgbuf;

	for (; parser->findidx + 1 < parser->msgsize; parser->findidx++)
	{
		if (buf[parser->findidx] == '\r' && buf[parser->findidx + 1] == '\n')
			return __redis_parse_line(parser);
	}

	return 2;
}

static int __redis_parse_nchar(redis_parser_t *parser)
{
	if (parser->nchar <= parser->msgsize - parser->msgidx)
	{
		redis_reply_set_string((const char *)parser->msgidx, parser->nchar,
							   parser->cur);

		parser->msgidx += parser->nchar;
		parser->status = REDIS_GET_CR;
		return 0;
	}

	return 2;
}

//-1 error | 0 continue | 1 finish-one | 2 not-enough
static int __redis_parser_forward(redis_parser_t *parser)
{
	char *buf = parser->msgbuf;

	if (parser->msgidx >= parser->msgsize)
		return 2;

	switch (parser->status)
	{
	case REDIS_GET_CMD:
		return __redis_parse_cmd(buf[parser->msgidx++], parser);

	case REDIS_GET_CR:
		return __redis_parse_cr(buf[parser->msgidx++], parser);

	case REDIS_GET_LF:
		return __redis_parse_lf(buf[parser->msgidx++], parser);

	case REDIS_UNTIL_CRLF:
		return __redis_parse_crlf(parser);

	case REDIS_GET_NCHAR:
		return __redis_parse_nchar(parser);
	}

	return -2;
}

void redis_parser_init(redis_parser_t *parser)
{
	redis_reply_init(&parser->reply);
	parser->parse_succ = 0;
	parser->msgbuf = NULL;
	parser->msgsize = 0;
	parser->bufsize = 0;
	//parser->status = REDIS_PARSE_INIT;
	//parser->nleft = 0;
	parser->status = REDIS_GET_CMD;
	parser->nleft = 1;
	parser->cur = &parser->reply;
	INIT_LIST_HEAD(&parser->read_list);
	parser->msgidx = 0;
	parser->cmd = '\0';
	parser->nchar = 0;
	parser->findidx = 0;
}

void redis_parser_deinit(redis_parser_t *parser)
{
	struct list_head *pos, *tmp;
	struct __redis_read_record *next;

	list_for_each_safe(pos, tmp, &parser->read_list)
	{
		next = list_entry(pos, struct __redis_read_record, list);
		list_del(pos);
		free(next);
	}

	redis_reply_deinit(&parser->reply);
	free(parser->msgbuf);
}

static int __redis_parse_done(redis_reply_t *reply, char *buf, int depth)
{
	size_t i;

	if (depth == REDIS_REPLY_DEPTH_LIMIT)
		return -2;

	switch (reply->type)
	{
	case REDIS_REPLY_TYPE_INTEGER:
		break;

	case REDIS_REPLY_TYPE_ARRAY:
		for (i = 0; i < reply->elements; i++)
		{
			if (__redis_parse_done(reply->element[i], buf, depth + 1) < 0)
				return -2;
		}

		break;

	case REDIS_REPLY_TYPE_STATUS:
	case REDIS_REPLY_TYPE_ERROR:
	case REDIS_REPLY_TYPE_STRING:
		reply->str = buf + (size_t)reply->str;
		break;
	}

	return 1;
}

static int __redis_split_inline_command(redis_parser_t *parser)
{
	char *msg = parser->msgbuf;
	char *end = msg + parser->msgsize;
	size_t arr_size = 0;
	redis_reply_t **ele;
	char *cur;
	int ret;

	while (msg != end)
	{
		while (msg != end && isspace(*msg))
			msg++;

		if (msg == end)
			break;

		arr_size++;

		while (msg != end && !isspace(*msg))
			msg++;
	}

	if (arr_size == 0)
	{
		parser->msgsize = 0;
		parser->msgidx = 0;
		return 0;
	}

	ret = redis_reply_set_array(arr_size, &parser->reply);
	if (ret < 0)
		return ret;

	ele = parser->reply.element;
	msg = parser->msgbuf;

	while (msg != end)
	{
		while (msg != end && isspace(*msg))
			msg++;

		if (msg == end)
			break;

		cur = msg;
		while (cur != end && !isspace(*cur))
			cur++;

		redis_reply_set_string(msg, cur - msg, *ele);

		msg = cur;
		ele++;
	}

	parser->status = REDIS_PARSE_END;
	return 1;
}

int redis_parser_append_message(const void *buf, size_t *size,
								redis_parser_t *parser)
{
	size_t msgsize_bak = parser->msgsize;

	if (parser->status == REDIS_PARSE_END)
	{
		*size = 0;
		return 1;
	}

	if (parser->msgsize + *size > parser->bufsize)
	{
		size_t new_size = MAX(REDIS_MSGBUF_INIT_SIZE, 2 * parser->bufsize);
		void *new_base;

		while (new_size < parser->msgsize + *size)
			new_size *= 2;

		new_base = realloc(parser->msgbuf, new_size);
		if (!new_base)
			return -1;

		parser->msgbuf = (char *)new_base;
		parser->bufsize = new_size;
	}

	memcpy(parser->msgbuf + parser->msgsize, buf, *size);
	parser->msgsize += *size;
	if (parser->msgsize > 0 && (isalpha(*parser->msgbuf) ||
								isspace(*parser->msgbuf)))
	{
		while (parser->msgidx < parser->msgsize &&
			*(parser->msgbuf + parser->msgidx) != '\n')
		{
			parser->msgidx++;
		}

		if (parser->msgidx == parser->msgsize)
			return 0;

		parser->msgidx++;
		parser->msgsize = parser->msgidx;
		*size = parser->msgsize - msgsize_bak;

		return __redis_split_inline_command(parser);
	}

	do
	{
		int ret = __redis_parser_forward(parser);

		if (ret < 0)
			return ret;

		if (ret == 1)
		{
			struct list_head *lnext = parser->read_list.next;
			struct __redis_read_record *next;

			parser->nleft--;
			if (lnext && lnext != &parser->read_list)
			{
				next = list_entry(lnext, struct __redis_read_record, list);
				parser->cur = next->reply;
				list_del(lnext);
				free(next);
			}

			if (parser->nleft > 0)
				parser->status = REDIS_GET_CMD;
			else
			{
				parser->parse_succ = 1;
				parser->status = REDIS_PARSE_END;
			}
		}
		else if (ret == 2)
			return 0;

	} while (parser->status != REDIS_PARSE_END);

	*size = parser->msgidx - msgsize_bak;
	return __redis_parse_done(&parser->reply, parser->msgbuf, 0);
}


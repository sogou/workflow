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
*/

#ifndef _REDIS_PARSER_H_
#define _REDIS_PARSER_H_

#include <stddef.h>
#include "list.h"

// redis_parser_t is absolutely same as hiredis-redisReply in memory
// If you include hiredis.h, redisReply* can cast to redis_reply_t* safely

#define REDIS_REPLY_TYPE_STRING 1
#define REDIS_REPLY_TYPE_ARRAY 2
#define REDIS_REPLY_TYPE_INTEGER 3
#define REDIS_REPLY_TYPE_NIL 4
#define REDIS_REPLY_TYPE_STATUS 5
#define REDIS_REPLY_TYPE_ERROR 6

typedef struct __redis_reply {
	int type; /* REDIS_REPLY_TYPE_* */
	long long integer; /* The integer when type is REDIS_REPLY_TYPE_INTEGER */
	size_t len; /* Length of string */
	char *str; /* Used for both REDIS_REPLY_TYPE_ERROR and REDIS_REPLY_TYPE_STRING */
	size_t elements; /* number of elements, for REDIS_REPLY_TYPE_ARRAY */
	struct __redis_reply **element; /* elements vector for REDIS_REPLY_TYPE_ARRAY */
} redis_reply_t;

typedef struct __redis_parser
{
	int parse_succ;//check first
	int status;
	char *msgbuf;
	size_t msgsize;
	size_t bufsize;
	redis_reply_t *cur;
	struct list_head read_list;
	size_t msgidx;
	size_t findidx;
	int nleft;
	int nchar;
	char cmd;
	redis_reply_t reply;
} redis_parser_t;

#ifdef __cplusplus
extern "C"
{
#endif

void redis_parser_init(redis_parser_t *parser);
void redis_parser_deinit(redis_parser_t *parser);
int redis_parser_append_message(const void *buf, size_t *size,
								redis_parser_t *parser);

void redis_reply_deinit(redis_reply_t *reply);

int redis_reply_set_array(size_t size, redis_reply_t *reply);

#ifdef __cplusplus
}
#endif

static inline void redis_reply_init(redis_reply_t *reply)
{
	reply->type = REDIS_REPLY_TYPE_NIL;
	reply->integer = 0;
	reply->len = 0;
	reply->str = NULL;
	reply->elements = 0;
	reply->element = NULL;
}

static inline void redis_reply_set_string(const char *str, size_t len,
										  redis_reply_t *reply)
{
	reply->type = REDIS_REPLY_TYPE_STRING;
	reply->len = len;
	reply->str = (char *)str;
}

static inline void redis_reply_set_integer(long long intv, redis_reply_t *reply)
{
	reply->type = REDIS_REPLY_TYPE_INTEGER;
	reply->integer = intv;
}

static inline void redis_reply_set_null(redis_reply_t *reply)
{
	reply->type = REDIS_REPLY_TYPE_NIL;
}

static inline void redis_reply_set_error(const char *err, size_t len,
										 redis_reply_t *reply)
{
	reply->type = REDIS_REPLY_TYPE_ERROR;
	reply->len = len;
	reply->str = (char *)err;
}

static inline void redis_reply_set_status(const char *str, size_t len,
										  redis_reply_t *reply)
{
	reply->type = REDIS_REPLY_TYPE_STATUS;
	reply->len = len;
	reply->str = (char *)str;
}

#endif


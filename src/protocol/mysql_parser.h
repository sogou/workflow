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

  Authors: Li Yingxin (liyingxin@sogou-inc.com)
*/

#ifndef _MYSQL_PARSER_H_
#define _MYSQL_PARSER_H_

#include <stddef.h>
#include "list.h"

// the first byte in response message
// from 1 to 0xfa means result_set field or data_row
// NULL is sent as 0xfb, will be treated as LOCAL_INLINE
// MySQL MESSAGE STATUS
enum
{
	MYSQL_PACKET_HEADER_OK		=	0,
	MYSQL_PACKET_HEADER_NULL	= 251, //0xfb
	MYSQL_PACKET_HEADER_EOF		= 254, //0xfe
	MYSQL_PACKET_HEADER_ERROR	= 255, //0xff
};

typedef struct __mysql_field
{
	size_t name_offset;			/* Name of column */
	size_t org_name_offset;		/* Original column name, if an alias */
	size_t table_offset;		/* Table of column if column was a field */
	size_t org_table_offset;	/* Org table name, if table was an alias */
	size_t db_offset;			/* Database for table */
	size_t catalog_offset;		/* Catalog for table */
	size_t def_offset;			/* Default value (set by mysql_list_fields) */
	int length;					/* Width of column (create length) */
	int name_length;
	int org_name_length;
	int table_length;
	int org_table_length;
	int db_length;
	int catalog_length;
	int def_length;
	int flags;					/* Div flags */
	int decimals;				/* Number of decimals in field */
	int charsetnr;				/* Character set */
	int data_type;				/* Type of field. See mysql_types.h for types */
//	void *extension;
} mysql_field_t;

struct __mysql_result_set
{
	struct list_head list;
	int type;
	int server_status;

	int field_count;
	int row_count;
	size_t rows_begin_offset;
	size_t rows_end_offset;
	mysql_field_t **fields;

	unsigned long long affected_rows;
	unsigned long long insert_id;
	int warning_count;
	size_t info_offset;
	int info_len;
};

typedef struct __mysql_result_set_cursor 
{
	const struct list_head *head;
	const struct list_head *current;
} mysql_result_set_cursor_t;

typedef struct __mysql_parser
{
	size_t offset;
	int cmd;
	int packet_type;
	int (*parse)(const void *, size_t, struct __mysql_parser *);

	size_t net_state_offset;		// err packet server_state
	size_t err_msg_offset; 			// -1 for default
	int err_msg_len;				// -1 for default

	size_t local_inline_offset; 	// local inline file name
	int local_inline_length;
	const void *buf;
	int error;

	int result_set_count;
	struct list_head result_set_list;
	struct __mysql_result_set *current_result_set;
	int current_field_count;
} mysql_parser_t;

#ifdef __cplusplus
extern "C"
{
#endif

void mysql_parser_init(mysql_parser_t *parser);
void mysql_parser_deinit(mysql_parser_t *parser);
void mysql_parser_get_info(const char **info_str,
							size_t *info_len,
							mysql_parser_t *parser);
void mysql_parser_get_net_state(const char **net_state_str,
								size_t *net_state_len,
								mysql_parser_t *parser);
void mysql_parser_get_err_msg(const char **err_msg_str,
							  size_t *err_msg_len,
							  mysql_parser_t *parser);
// if append check get 0, don`t need to parse()
// if append check get 1, parse and tell them if this is all the package
//
// ret: 1: this ResultSet is received finished
//      0: this ResultSet is not recieved finished
//	   -1: system error
//	   -2: bad message error
int mysql_parser_parse(const void *buf, size_t len, mysql_parser_t *parser);

#ifdef __cplusplus
}
#endif

static inline void mysql_parser_set_command(int cmd, mysql_parser_t *parser)
{
	parser->cmd = cmd;
}

static inline void mysql_parser_get_local_inline(const char **local_inline_name,
												 size_t *local_inline_len,
												 mysql_parser_t *parser)
{
	*local_inline_name = (const char *)parser->buf + parser->local_inline_offset;
	*local_inline_len = parser->local_inline_length;
}

static inline void mysql_result_set_cursor_init(mysql_result_set_cursor_t *cursor,
												mysql_parser_t *parser)
{
	cursor->head = &parser->result_set_list;
	cursor->current = cursor->head;
}

static inline void mysql_result_set_cursor_rewind(mysql_result_set_cursor_t *cursor)
{
	cursor->current = cursor->head;
}

static inline void mysql_result_set_cursor_deinit(mysql_result_set_cursor_t *cursor)
{
}

static inline int mysql_result_set_cursor_next(struct __mysql_result_set **result_set,
											   mysql_result_set_cursor_t *cursor)
{
	if (cursor->current->next != cursor->head)
	{
		cursor->current = cursor->current->next;
		*result_set = list_entry(cursor->current, struct __mysql_result_set, list);
		return 0;
	}
	return 1;
}

#endif

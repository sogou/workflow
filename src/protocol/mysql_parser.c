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

#include <stdlib.h>
#include "mysql_types.h"
#include "mysql_byteorder.h"
#include "mysql_parser.h"

static int parse_base_packet(const void *buf, size_t len, mysql_parser_t *parser);

static int parse_error_packet(const void *buf, size_t len, mysql_parser_t *parser);

static int parse_ok_packet(const void *buf, size_t len, mysql_parser_t *parser);

static int parse_eof_packet(const void *buf, size_t len, mysql_parser_t *parser);

static int parse_field_eof_packet(const void *buf, size_t len, mysql_parser_t *parser);

static int parse_field_count(const void *buf, size_t len, mysql_parser_t *parser);

static int parse_column_def_packet(const void *buf, size_t len, mysql_parser_t *parser);

static int parse_local_inline(const void *buf, size_t len, mysql_parser_t *parser);

static int parse_row_packet(const void *buf, size_t len, mysql_parser_t *parser);

void mysql_parser_init(mysql_parser_t *parser)
{
	parser->offset = 0;
	parser->cmd = MYSQL_COM_QUERY;
	parser->packet_type = MYSQL_PACKET_OTHER;
	parser->parse = parse_base_packet;
	parser->result_set_count = 0;
	INIT_LIST_HEAD(&parser->result_set_list);
}

void mysql_parser_deinit(mysql_parser_t *parser)
{
	struct __mysql_result_set *result_set;
	struct list_head *pos, *tmp;
	int i;

	list_for_each_safe(pos, tmp, &parser->result_set_list)
	{
		result_set = list_entry(pos, struct __mysql_result_set, list);
		list_del(pos);

		if (result_set->field_count)
		{
			for (i = 0; i < result_set->field_count; i++)
				free(result_set->fields[i]);

			free(result_set->fields);
		}

		free(result_set);
	}
}

int mysql_parser_parse(const void *buf, size_t len, mysql_parser_t *parser)
{
//	const char *end = (const char *)buf + len;
	int ret;

	do {
		ret = parser->parse(buf, len, parser);
		if (ret < 0)
			return ret;

		if (ret > 0 && parser->offset != len)
			return -2;

	} while (parser->offset < len);

	return ret;
}

void mysql_parser_get_net_state(const char **net_state_str,
								size_t *net_state_len,
								mysql_parser_t *parser)
{
	*net_state_str = (const char *)parser->buf + parser->net_state_offset;
	*net_state_len = MYSQL_STATE_LENGTH;
}

void mysql_parser_get_err_msg(const char **err_msg_str,
							  size_t *err_msg_len,
							  mysql_parser_t *parser)
{
	if (parser->err_msg_offset == (size_t)-1 && parser->err_msg_len == 0)
	{
		*err_msg_str = MYSQL_STATE_DEFAULT;
		*err_msg_len = MYSQL_STATE_LENGTH;
	} else {
		*err_msg_str = (const char *)parser->buf + parser->err_msg_offset;
		*err_msg_len = parser->err_msg_len;
	}
}

static int parse_base_packet(const void *buf, size_t len, mysql_parser_t *parser)
{
	const unsigned char *p = (const unsigned char *)buf + parser->offset;

	switch (*p)
	{
	// OK PACKET
	case MYSQL_PACKET_HEADER_OK:
		parser->parse = parse_ok_packet;
		break;
	// ERR PACKET
	case MYSQL_PACKET_HEADER_ERROR:
		parser->parse = parse_error_packet;
		break;
	// EOF PACKET
	case MYSQL_PACKET_HEADER_EOF:
		parser->parse = parse_eof_packet;
		break;
	// LOCAL INFILE PACKET
	case MYSQL_PACKET_HEADER_NULL:
		// if (field_count == -1)
		parser->parse = parse_local_inline;
		break;
	default:
		parser->parse = parse_field_count;
		break;
	}

	return 0;
}

// 1:0xFF|2:err_no|1:#|5:server_state|0-512:err_msg
static int parse_error_packet(const void *buf, size_t len, mysql_parser_t *parser)
{
	const unsigned char *p = (const unsigned char *)buf + parser->offset;
	const unsigned char *buf_end = (const unsigned char *)buf + len;

	if (p + 9 > buf_end)
		return -2;

	parser->error = uint2korr(p + 1);
	p += 3;

	if (*p == '#')
	{
		p += 1;
		parser->net_state_offset = p - (const unsigned char *)buf;
		p += MYSQL_STATE_LENGTH;

		size_t msg_len = len - parser->offset - 9;
		parser->err_msg_offset = p - (const unsigned char *)buf;
		parser->err_msg_len = msg_len;
	} else {
		parser->err_msg_offset = (size_t)-1;
		parser->err_msg_len = 0;
	}

	parser->offset = len;
	parser->packet_type = MYSQL_PACKET_ERROR;
	parser->buf = buf;
	return 1;
}

// 1:0x00|1-9:affect_row|1-9:insert_id|2:server_status|2:warning_count|0-n:server_msg
static int parse_ok_packet(const void *buf, size_t len, mysql_parser_t *parser)
{
	const unsigned char *p = (const unsigned char *)buf + parser->offset;
	const unsigned char *buf_end = (const unsigned char *)buf + len;

	unsigned long long affected_rows, insert_id, info_len;
	const unsigned char *str;
	struct __mysql_result_set *result_set;
	unsigned int warning_count;
	int server_status;

	p += 1;// 0x00
	if (decode_length_safe(&affected_rows, &p, buf_end) <= 0)
		return -2;

	if (decode_length_safe(&insert_id, &p, buf_end) <= 0)
		return -2;

	if (p + 4 > buf_end)
		return -2;

	server_status = uint2korr(p);
	p += 2;
	warning_count = uint2korr(p);
	p += 2;

	if (p != buf_end)
	{
		if (decode_string(&str, &info_len, &p, buf_end) == 0)
			return -2;

		if (p != buf_end)
		{
			if (server_status & MYSQL_SERVER_SESSION_STATE_CHANGED)
			{
				const unsigned char *tmp_str;
				unsigned long long tmp_len;
				if (decode_string(&tmp_str, &tmp_len, &p, buf_end) == 0)
					return -2;
			} else
				return -2;
		}
	} else {
		str = p;
		info_len = 0;
	}

	result_set = (struct __mysql_result_set *)malloc(sizeof(struct __mysql_result_set));
	if (result_set == NULL)
		return -1;

	result_set->info_offset = str - (const unsigned char *)buf;
	result_set->info_len = info_len;
	result_set->affected_rows = (affected_rows == ~0ULL) ? 0 : affected_rows;
	result_set->insert_id = (insert_id == ~0ULL) ? 0 : insert_id;
	result_set->server_status = server_status;
	result_set->warning_count = warning_count;
	result_set->type = MYSQL_PACKET_OK;
	result_set->field_count = 0;

	list_add_tail(&result_set->list, &parser->result_set_list);
	parser->current_result_set = result_set;
	parser->result_set_count++;
	parser->packet_type = MYSQL_PACKET_OK;

	parser->buf = buf;
	parser->offset = p - (const unsigned char *)buf;

	if (server_status & MYSQL_SERVER_MORE_RESULTS_EXIST)
	{
		parser->parse = parse_base_packet;
		return 0;
	}

	return 1;
}

// 1:0xfe|2:warnings|2:status_flag
static int parse_eof_packet(const void *buf, size_t len, mysql_parser_t *parser)
{
	const unsigned char *p = (const unsigned char *)buf + parser->offset;
	const unsigned char *buf_end = (const unsigned char *)buf + len;

	if (p + 5 > buf_end)
		return -2;

	parser->offset += 5;
	parser->packet_type = MYSQL_PACKET_EOF;
	parser->buf = buf;

	int status_flag = uint2korr(p + 3);
	if (status_flag & MYSQL_SERVER_MORE_RESULTS_EXIST)
	{
		parser->parse = parse_base_packet;
		return 0;
	}

	return 1;
}

static int parse_field_eof_packet(const void *buf, size_t len, mysql_parser_t *parser)
{
	const unsigned char *p = (const unsigned char *)buf + parser->offset;
	const unsigned char *buf_end = (const unsigned char *)buf + len;

	if (p + 5 > buf_end)
		return -2;

	parser->offset += 5;
	parser->current_result_set->rows_begin_offset = parser->offset;
	parser->parse = parse_row_packet;
	return 0;
}

//raw file data
static int parse_local_inline(const void *buf, size_t len, mysql_parser_t *parser)
{
	parser->local_inline_offset = parser->offset;
	parser->local_inline_length = len - parser->offset;
	parser->offset = len;
	parser->packet_type = MYSQL_PACKET_LOCAL_INLINE;
	parser->buf = buf;
	return 1;
}

// for each field:
// NULL as 0xfb, or a length-encoded-string
static int parse_row_packet(const void *buf, size_t len, mysql_parser_t *parser)
{
	const unsigned char *p = (const unsigned char *)buf + parser->offset;
	const unsigned char *buf_end = (const unsigned char *)buf + len;

	unsigned long long cell_len;
	const unsigned char *cell_data;

	size_t i;

	if (*p == MYSQL_PACKET_HEADER_ERROR)
	{
		parser->parse = parse_error_packet;
		return 0;
	}

	if (*p == MYSQL_PACKET_HEADER_EOF)
	{
		parser->parse = parse_eof_packet;
		parser->current_result_set->rows_end_offset = parser->offset;

		return 0;
	}

	for (i = 0; i < parser->current_result_set->field_count; i++)
	{
		if (*p == MYSQL_PACKET_HEADER_NULL)
		{
			p++;
		} else {
			if (decode_string(&cell_data, &cell_len, &p, buf_end) == 0)
				break;
		}
	}

	if (i != parser->current_result_set->field_count)
		return -2;

	parser->current_result_set->row_count++;
	parser->offset = p - (const unsigned char *)buf;
	return 0;
}

static int parse_field_count(const void *buf, size_t len, mysql_parser_t *parser)
{
	const unsigned char *p = (const unsigned char *)buf + parser->offset;
	const unsigned char *buf_end = (const unsigned char *)buf + len;

	unsigned long long field_count;
	struct __mysql_result_set *result_set;

	if (decode_length_safe(&field_count, &p, buf_end) <= 0)
		return -2;

	field_count = (field_count == ~0ULL) ? 0 : field_count;

	if (field_count)
	{
		result_set = (struct __mysql_result_set *)malloc(sizeof (struct __mysql_result_set));
		if (result_set == NULL)
			return -1;

		result_set->fields = (mysql_field_t **)calloc(field_count, sizeof (mysql_field_t *));
		if (result_set->fields == NULL)
		{
			free(result_set);
			return -1;
		}

		result_set->field_count = field_count;
		result_set->row_count = 0;
		result_set->type = MYSQL_PACKET_GET_RESULT;

		list_add_tail(&result_set->list, &parser->result_set_list);
		parser->current_result_set = result_set;
		parser->current_field_count = 0;
		parser->result_set_count++;
		parser->packet_type = MYSQL_PACKET_GET_RESULT;

		parser->parse = parse_column_def_packet;
		parser->offset = p - (const unsigned char *)buf;
	} else {
		parser->parse = parse_ok_packet;
	}
	return 0;
}

// COLUMN DEFINATION PACKET. for one field: (after protocol 41)
// str:catalog|str:db|str:table|str:org_table|str:name|str:org_name|
// 2:charsetnr|4:length|1:type|2:flags|1:decimals|1:0x00|1:0x00|n:str(if COM_FIELD_LIST)
static int parse_column_def_packet(const void *buf, size_t len, mysql_parser_t *parser)
{
	const unsigned char *p = (const unsigned char *)buf + parser->offset;
	const unsigned char *buf_end = (const unsigned char *)buf + len;

	int flag = 0;
	const unsigned char *str;
	unsigned long long str_len;
	mysql_field_t *field = (mysql_field_t *)malloc(sizeof(mysql_field_t));

	if (!field)
		return -1;

	do {
		if (decode_string(&str, &str_len, &p, buf_end) == 0)
			break;
		field->catalog_offset = str - (const unsigned char *)buf;
		field->catalog_length = str_len;

		if (decode_string(&str, &str_len, &p, buf_end) == 0)
			break;
		field->db_offset = str - (const unsigned char *)buf;
		field->db_length = str_len;

		if (decode_string(&str, &str_len, &p, buf_end) == 0)
			break;
		field->table_offset = str - (const unsigned char *)buf;
		field->table_length = str_len;

		if (decode_string(&str, &str_len, &p, buf_end) == 0)
			break;
		field->org_table_offset = str - (const unsigned char *)buf;
		field->org_table_length = str_len;

		if (decode_string(&str, &str_len, &p, buf_end) == 0)
			break;
		field->name_offset = str - (const unsigned char *)buf;
		field->name_length = str_len;

		if (decode_string(&str, &str_len, &p, buf_end) == 0)
			break;
		field->org_name_offset = str - (const unsigned char *)buf;
		field->org_name_length = str_len;

		// the rest needs at least 13
		if (p + 13 > buf_end)
			break;

		p++; // length of the following fields (always 0x0c)
		field->charsetnr = uint2korr(p);
		field->length = uint4korr(p + 2);
		field->data_type = *(p + 6);
		field->flags = uint2korr(p + 7);
		field->decimals = (int)p[9];
		p += 12;
		// if is COM_FIELD_LIST, the rest is a string
		// 0x03 for COM_QUERY
		if (parser->cmd == MYSQL_COM_FIELD_LIST)
		{
			if (decode_string(&str, &str_len, &p, buf_end) == 0)
				break;
			field->def_offset = str - (const unsigned char *)buf;
			field->def_length = str_len;
		} else {
			field->def_offset = (size_t)-1;
			field->def_length = 0;
		}
		flag = 1;
	} while (0);

	if (flag == 0)
	{
		free(field);
		return -2;
	}

	//parser->fields.emplace_back(std::move(field));
	parser->current_result_set->fields[parser->current_field_count] = field;

	parser->offset = p - (const unsigned char *)buf;
	if (++parser->current_field_count == parser->current_result_set->field_count)
		parser->parse = parse_field_eof_packet;

	return 0;
}


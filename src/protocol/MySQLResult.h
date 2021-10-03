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

#ifndef _MYSQLRESULT_H_
#define _MYSQLRESULT_H_

#include <map>
#include <vector>
#include <string>
#include <unordered_map>
#include "mysql_types.h"
#include "mysql_parser.h"
#include "MySQLMessage.h"

/**
 * @file   MySQLResult.h
 * @brief  MySQL toolbox for visit result
 */

namespace protocol
{

class MySQLCell
{
public:
	MySQLCell();

	MySQLCell(MySQLCell&& move);
	MySQLCell& operator=(MySQLCell&& move);

	MySQLCell(const void *data, size_t len, int data_type);

	int get_data_type() const;

	bool is_null() const;
	bool is_int() const;
	bool is_string() const;
	bool is_float() const;
	bool is_double() const;
	bool is_ulonglong() const;
	bool is_date() const;
	bool is_time() const;
	bool is_datetime() const;

	// for copy
	int as_int() const;
	std::string as_string() const;	
	std::string as_binary_string() const;	
	float as_float() const;
	double as_double() const;
	unsigned long long as_ulonglong() const;
	std::string as_date() const;
	std::string as_time() const;
	std::string as_datetime() const;

	// for nocopy
	void get_cell_nocopy(const void **data, size_t *len, int *data_type) const;

private:
	int data_type;
	void *data;
	size_t len;
};

class MySQLField
{
public:
	MySQLField(const void *buf, mysql_field_t *field);

	std::string get_name() const;
	std::string get_org_name() const;
	std::string get_table() const;
	std::string get_org_table() const;
	std::string get_db() const;
	std::string get_catalog() const;
	std::string get_def() const;
	int get_charsetnr() const;
	int get_length() const;
	int get_flags() const;
	int get_decimals() const;
	int get_data_type() const;

private:
	const char *name;			/* Name of column */
	const char *org_name;		/* Original column name, if an alias */
	const char *table;			/* Table of column if column was a field */
	const char *org_table;		/* Org table name, if table was an alias */
	const char *db;				/* Database for table */
	const char *catalog;		/* Catalog for table */
	const char *def;			/* Default value (set by mysql_list_fields) */
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
};

class MySQLResultCursor
{
public:
	MySQLResultCursor(const MySQLResponse *resp);

	MySQLResultCursor(MySQLResultCursor&& move);
	MySQLResultCursor& operator=(MySQLResultCursor&& move);

	virtual ~MySQLResultCursor();

	bool next_result_set();
	void first_result_set();

	const MySQLField *fetch_field();
	const MySQLField *const *fetch_fields() const;

	bool fetch_row(std::vector<MySQLCell>& row_arr);
	bool fetch_row(std::map<std::string, MySQLCell>& row_map);
	bool fetch_row(std::unordered_map<std::string, MySQLCell>& row_map);

	bool fetch_row_nocopy(const void **data, size_t *len, int *data_type);
	bool fetch_all(std::vector<std::vector<MySQLCell>>& rows);

	int get_cursor_status() const;
	int get_server_status() const;

	int get_field_count() const;
	int get_rows_count() const;
	unsigned long long get_affected_rows() const;
	unsigned long long get_insert_id() const;
	int get_warnings() const;
	std::string get_info() const;

	void rewind();

public:
	MySQLResultCursor();
	void reset(MySQLResponse *resp);

private:
	void init(const MySQLResponse *resp);
	void init();
	void clear();

	void fetch_result_set(const struct __mysql_result_set *result_set);

	template<class T>
	bool fetch_row(T& row_map); 

	int status;
	int server_status;
	const void *start;
	const void *end;
	const void *pos;

	const void **row_data;
	MySQLField **fields;
	int row_count;
	int field_count;
	int current_row;
	int current_field;

	unsigned long long affected_rows;
	unsigned long long insert_id;
	int warning_count;
	int info_len;

	mysql_result_set_cursor_t cursor;
	mysql_parser_t *parser;
};

}

#include "MySQLResult.inl"

#endif


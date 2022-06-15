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
		   Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

#ifndef _MYSQL_TYPES_H_
#define _MYSQL_TYPES_H_

#define MYSQL_STATE_LENGTH			5
#define MYSQL_STATE_DEFAULT			"HY000"

// may be set by server in EOF/OK packet
#define MYSQL_SERVER_MORE_RESULTS_EXIST		0x0008

enum
{
	MYSQL_COM_SLEEP,
	MYSQL_COM_QUIT,
	MYSQL_COM_INIT_DB,
	MYSQL_COM_QUERY,
	MYSQL_COM_FIELD_LIST,
	MYSQL_COM_CREATE_DB,
	MYSQL_COM_DROP_DB,
	MYSQL_COM_REFRESH,
	MYSQL_COM_DEPRECATED_1,
	MYSQL_COM_STATISTICS,
	MYSQL_COM_PROCESS_INFO,
	MYSQL_COM_CONNECT,
	MYSQL_COM_PROCESS_KILL,
	MYSQL_COM_DEBUG,
	MYSQL_COM_PING,
	MYSQL_COM_TIME,
	MYSQL_COM_DELAYED_INSERT,
	MYSQL_COM_CHANGE_USER,
	MYSQL_COM_BINLOG_DUMP,
	MYSQL_COM_TABLE_DUMP,
	MYSQL_COM_CONNECT_OUT,
	MYSQL_COM_REGISTER_SLAVE,
	MYSQL_COM_STMT_PREPARE,
	MYSQL_COM_STMT_EXECUTE,
	MYSQL_COM_STMT_SEND_LONG_DATA,
	MYSQL_COM_STMT_CLOSE,
	MYSQL_COM_STMT_RESET,
	MYSQL_COM_SET_OPTION,
	MYSQL_COM_STMT_FETCH,
	MYSQL_COM_DAEMON,
	MYSQL_COM_BINLOG_DUMP_GTID,
	MYSQL_COM_RESET_CONNECTION,
	MYSQL_COM_CLONE,
	MYSQL_COM_END
};

// MySQL packet type
enum
{
	MYSQL_PACKET_OTHER	=	0,
	MYSQL_PACKET_OK,
	MYSQL_PACKET_NULL,
	MYSQL_PACKET_EOF,
	MYSQL_PACKET_ERROR,
	MYSQL_PACKET_GET_RESULT,
	MYSQL_PACKET_LOCAL_INLINE,
};

// MySQL cursor status
enum
{
	MYSQL_STATUS_NOT_INIT	=	0,
	MYSQL_STATUS_OK,
	MYSQL_STATUS_GET_RESULT,
	MYSQL_STATUS_ERROR,
	MYSQL_STATUS_END,
};

// Column types for MySQL
enum
{
	MYSQL_TYPE_DECIMAL	=	0,
	MYSQL_TYPE_TINY,
	MYSQL_TYPE_SHORT,
	MYSQL_TYPE_LONG,
	MYSQL_TYPE_FLOAT,
	MYSQL_TYPE_DOUBLE,
	MYSQL_TYPE_NULL,
	MYSQL_TYPE_TIMESTAMP,
	MYSQL_TYPE_LONGLONG,
	MYSQL_TYPE_INT24,
	MYSQL_TYPE_DATE,
	MYSQL_TYPE_TIME,
	MYSQL_TYPE_DATETIME,
	MYSQL_TYPE_YEAR,
	MYSQL_TYPE_NEWDATE,				// Internal to MySQL. Not used in protocol
	MYSQL_TYPE_VARCHAR,
	MYSQL_TYPE_BIT,
	MYSQL_TYPE_TIMESTAMP2,
	MYSQL_TYPE_DATETIME2,			// Internal to MySQL. Not used in protocol
	MYSQL_TYPE_TIME2,				// Internal to MySQL. Not used in protocol
	MYSQL_TYPE_TYPED_ARRAY = 244,	// Used for replication only
	MYSQL_TYPE_JSON = 245,
	MYSQL_TYPE_NEWDECIMAL = 246,
	MYSQL_TYPE_ENUM = 247,
	MYSQL_TYPE_SET = 248,
	MYSQL_TYPE_TINY_BLOB = 249,
	MYSQL_TYPE_MEDIUM_BLOB = 250,
	MYSQL_TYPE_LONG_BLOB = 251,
	MYSQL_TYPE_BLOB = 252,
	MYSQL_TYPE_VAR_STRING = 253,
	MYSQL_TYPE_STRING = 254,
	MYSQL_TYPE_GEOMETRY = 255
};

static inline const char *datatype2str(int data_type)
{
	switch (data_type)
	{
	case MYSQL_TYPE_BIT:
		return "BIT";

	case MYSQL_TYPE_BLOB:
		return "BLOB";

	case MYSQL_TYPE_DATE:
		return "DATE";

	case MYSQL_TYPE_DATETIME:
		return "DATETIME";

	case MYSQL_TYPE_NEWDECIMAL:
		return "NEWDECIMAL";

	case MYSQL_TYPE_DECIMAL:
		return "DECIMAL";

	case MYSQL_TYPE_DOUBLE:
		return "DOUBLE";

	case MYSQL_TYPE_ENUM:
		return "ENUM";

	case MYSQL_TYPE_FLOAT:
		return "FLOAT";

	case MYSQL_TYPE_GEOMETRY:
		return "GEOMETRY";

	case MYSQL_TYPE_INT24:
		return "INT24";

	case MYSQL_TYPE_JSON:
		return "JSON";

	case MYSQL_TYPE_LONG:
		return "LONG";

	case MYSQL_TYPE_LONGLONG:
		return "LONGLONG";

	case MYSQL_TYPE_LONG_BLOB:
		return "LONG_BLOB";

	case MYSQL_TYPE_MEDIUM_BLOB:
		return "MEDIUM_BLOB";

	case MYSQL_TYPE_NEWDATE:
		return "NEWDATE";

	case MYSQL_TYPE_NULL:
		return "NULL";

	case MYSQL_TYPE_SET:
		return "SET";

	case MYSQL_TYPE_SHORT:
		return "SHORT";

	case MYSQL_TYPE_STRING:
		return "STRING";

	case MYSQL_TYPE_TIME:
		return "TIME";

	case MYSQL_TYPE_TIMESTAMP:
		return "TIMESTAMP";

	case MYSQL_TYPE_TINY:
		return "TINY";

	case MYSQL_TYPE_TINY_BLOB:
		return "TINY_BLOB";

	case MYSQL_TYPE_VAR_STRING:
		return "VAR_STRING";

	case MYSQL_TYPE_YEAR:
		return "YEAR";

	default:
		return "?-unknown-?";

	}
}

#endif


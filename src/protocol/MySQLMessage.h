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

#ifndef _MYSQLMESSAGE_H_
#define _MYSQLMESSAGE_H_

#include <stdint.h>
#include <string>
#include "ProtocolMessage.h"
#include "mysql_stream.h"
#include "mysql_parser.h"

/**
 * @file   MySQLMessage.h
 * @brief  MySQL Protocol Interface
 */

namespace protocol
{

class MySQLMessage : public ProtocolMessage
{
public:
	mysql_parser_t *get_parser() const;
	int get_seqid() const;
	void set_seqid(int seqid);
	int get_command() const;

protected:
	virtual int append(const void *buf, size_t *size);
	virtual int encode(struct iovec vectors[], int max);
	virtual int decode_packet(const unsigned char *buf, size_t buflen) { return 1; }

	void set_command(int cmd) const;

	//append
	mysql_stream_t *stream_;
	mysql_parser_t *parser_;

	//encode
	unsigned char heads_[256][4];
	uint8_t seqid_;
	std::string buf_;
	size_t cur_size_;

public:
	MySQLMessage();
	virtual ~MySQLMessage();
	//move constructor
	MySQLMessage(MySQLMessage&& move);
	//move operator
	MySQLMessage& operator= (MySQLMessage&& move);
};

class MySQLRequest : public MySQLMessage
{
public:
	void set_query(const char *query);
	void set_query(const std::string& query);
	void set_query(const char *query, size_t length);

	std::string get_query() const;
	bool query_is_unset() const;

public:
	MySQLRequest() = default;
	//move constructor
	MySQLRequest(MySQLRequest&& move) = default;
	//move operator
	MySQLRequest& operator= (MySQLRequest&& move) = default;
};

class MySQLResponse : public MySQLMessage
{
public:
	bool is_ok_packet() const;
	bool is_error_packet() const;
	int get_packet_type() const;

	unsigned long long get_affected_rows() const;
	unsigned long long get_last_insert_id() const;
	int get_warnings() const;
	int get_error_code() const;
	std::string get_error_msg() const;
	std::string get_sql_state() const;
	std::string get_info() const;

	void set_ok_packet();

public:
	MySQLResponse() = default;
	//move constructor
	MySQLResponse(MySQLResponse&& move) = default;
	//move operator
	MySQLResponse& operator= (MySQLResponse&& move) = default;

protected:
	virtual int decode_packet(const unsigned char *buf, size_t buflen);
};

}

//impl. not for user
#include "MySQLMessage.inl"

#endif


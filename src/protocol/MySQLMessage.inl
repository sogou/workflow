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
           Xie Han (xiehan@sogou-inc.com)
*/

#include <stdint.h>
#include <string.h>
#include <string>
#include <openssl/ssl.h>
#include "SSLWrapper.h"

namespace protocol
{

class MySQLHandshakeRequest : public MySQLRequest
{
private:
	virtual int encode(struct iovec vectors[], int max) { return 0; }
};

class MySQLHandshakeResponse : public MySQLResponse
{
public:
	void get_challenge(char *arr) const
	{
		memcpy(arr, auth_plugin_data_part_1_, 8);
		memcpy(arr + 8, auth_plugin_data_part_2_, 12);
	}

	virtual int encode(struct iovec vectors[], int max);

	void server_set(uint8_t protocol_version, const std::string server_version,
					uint32_t connection_id, const uint8_t *auth1,
					uint32_t capability_flags, uint8_t character_set,
					uint16_t status_flags, const uint8_t *auth2)
	{
		protocol_version_ = protocol_version;
		server_version_ = server_version;
		connection_id_ = connection_id;
		memcpy(auth_plugin_data_part_1_, auth1, 8);
		capability_flags_ = capability_flags;
		character_set_ = character_set;
		status_flags_ = status_flags;
		memcpy(auth_plugin_data_part_2_, auth2, 12);
	}

	bool host_disallowed() const { return disallowed_; }
	uint32_t get_capability_flags() const { return capability_flags_; }
	uint16_t get_status_flags() const { return status_flags_; }

private:
	virtual int decode_packet(const unsigned char *buf, size_t buflen);

	uint8_t protocol_version_;
	std::string server_version_;
	uint32_t connection_id_;
	uint8_t auth_plugin_data_part_1_[8];
	uint32_t capability_flags_;
	uint8_t character_set_;
	uint16_t status_flags_;
	uint8_t auth_plugin_data_part_2_[12];
	bool disallowed_;

public:
	MySQLHandshakeResponse() : disallowed_(false) { }
	//move constructor
	MySQLHandshakeResponse(MySQLHandshakeResponse&& move) = default;
	//move operator
	MySQLHandshakeResponse& operator= (MySQLHandshakeResponse&& move) = default;
};

class MySQLSSLRequest : public MySQLRequest
{
private:
	virtual int encode(struct iovec vectors[], int max);

	/* Do not support server side with SSL currently. */
	virtual int decode_packet(const unsigned char *buf, size_t buflen)
	{
		return -2;
	}

private:
	int character_set_;
	SSLHandshaker ssl_handshaker_;

public:
	MySQLSSLRequest(int character_set, SSL *ssl) : ssl_handshaker_(ssl)
	{
		character_set_ = character_set;
	}

	MySQLSSLRequest(MySQLSSLRequest&& move) = default;
	MySQLSSLRequest& operator= (MySQLSSLRequest&& move) = default;
};

class MySQLAuthRequest : public MySQLRequest
{
public:
	void set_auth(const std::string& username,
				  const std::string& password,
				  const std::string& db,
				  int character_set)
	{
		username_ = username;
		password_ = password;
		db_ = db;
		character_set_ = character_set;
	}

	void set_challenge(const char *arr)
	{
		challenge_.assign(arr, 20);
	}

private:
	virtual int encode(struct iovec vectors[], int max);
	virtual int decode_packet(const unsigned char *buf, size_t buflen);

	std::string username_;
	std::string password_;
	std::string db_;
	std::string challenge_;
	int character_set_;

public:
	MySQLAuthRequest() : character_set_(33) { }
	//move constructor
	MySQLAuthRequest(MySQLAuthRequest&& move) = default;
	//move operator
	MySQLAuthRequest& operator= (MySQLAuthRequest&& move) = default;
};

using MySQLAuthResponse = MySQLResponse;

//////////

inline mysql_parser_t *MySQLMessage::get_parser() const
{
	return parser_;
}

inline int MySQLMessage::get_seqid() const
{
	return seqid_;
}

inline void MySQLMessage::set_seqid(int seqid)
{
	seqid_ = seqid;
}

inline int MySQLMessage::get_command() const
{
	return parser_->cmd;
}

inline void MySQLMessage::set_command(int cmd) const
{
	mysql_parser_set_command(cmd, parser_);
}

inline MySQLMessage::MySQLMessage():
	stream_(new mysql_stream_t),
	parser_(new mysql_parser_t),
	seqid_(0),
	cur_size_(0)
{
	mysql_stream_init(stream_);
	mysql_parser_init(parser_);
}

inline bool MySQLRequest::query_is_unset() const
{
	return buf_.empty();
}

inline void MySQLRequest::set_query(const char *query)
{
	set_query(query, strlen(query));
}

inline void MySQLRequest::set_query(const std::string& query)
{
	set_query(query.c_str(), query.size());
}

inline int MySQLResponse::get_packet_type() const
{
	return parser_->packet_type;
}

inline int MySQLResponse::get_error_code() const
{
	return is_error_packet() ? parser_->error : 0;
}

inline std::string MySQLResponse::get_error_msg() const
{
	if (is_error_packet())
	{
		const char *s;
		size_t slen;

		mysql_parser_get_err_msg(&s, &slen, parser_);
		if (slen > 0)
			return std::string(s, slen);
	}

	return std::string();
}

inline std::string MySQLResponse::get_sql_state() const
{
	if (is_error_packet())
	{
		const char *s;
		size_t slen;

		mysql_parser_get_net_state(&s, &slen, parser_);
		if (slen > 0)
			return std::string(s, slen);
	}

	return std::string();
}

}


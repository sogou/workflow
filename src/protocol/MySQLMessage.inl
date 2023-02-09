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

  Authors: Xie Han (xiehan@sogou-inc.com)
           Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

#include <stdint.h>
#include <string.h>
#include <utility>
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
	std::string get_server_version() const { return server_version_; }
	std::string get_auth_plugin_name() const { return auth_plugin_name_; }

	void get_seed(unsigned char seed[20]) const
	{
		memcpy(seed, auth_plugin_data_, 20);
	}

	virtual int encode(struct iovec vectors[], int max);

	void server_set(uint8_t protocol_version, const std::string server_version,
					uint32_t connection_id, const unsigned char seed[20],
					uint32_t capability_flags, uint8_t character_set,
					uint16_t status_flags)
	{
		protocol_version_ = protocol_version;
		server_version_ = server_version;
		connection_id_ = connection_id;
		memcpy(auth_plugin_data_, seed, 20);
		capability_flags_ = capability_flags;
		character_set_ = character_set;
		status_flags_ = status_flags;
	}

	bool host_disallowed() const { return disallowed_; }
	uint32_t get_capability_flags() const { return capability_flags_; }
	uint16_t get_status_flags() const { return status_flags_; }

private:
	virtual int decode_packet(const unsigned char *buf, size_t buflen);

	std::string server_version_;
	std::string auth_plugin_name_;
	unsigned char auth_plugin_data_[20];
	uint32_t connection_id_;
	uint32_t capability_flags_;
	uint16_t status_flags_;
	uint8_t character_set_;
	uint8_t auth_plugin_data_len_;
	uint8_t protocol_version_;
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
	void set_auth(const std::string username,
				  const std::string password,
				  const std::string db,
				  int character_set)
	{
		username_ = std::move(username);
		password_ = std::move(password);
		db_ = std::move(db);
		character_set_ = character_set;
	}

	void set_auth_plugin_name(std::string name)
	{
		auth_plugin_name_ = std::move(name);
	}

	void set_seed(const unsigned char seed[20])
	{
		memcpy(seed_, seed, 20);
	}

private:
	virtual int encode(struct iovec vectors[], int max);
	virtual int decode_packet(const unsigned char *buf, size_t buflen);

	std::string username_;
	std::string password_;
	std::string db_;
	std::string auth_plugin_name_;
	unsigned char seed_[20];
	int character_set_;

public:
	MySQLAuthRequest() : character_set_(33) { }
	//move constructor
	MySQLAuthRequest(MySQLAuthRequest&& move) = default;
	//move operator
	MySQLAuthRequest& operator= (MySQLAuthRequest&& move) = default;
};

class MySQLAuthResponse : public MySQLResponse
{
public:
	std::string get_auth_plugin_name() const { return auth_plugin_name_; }

	void get_seed(unsigned char seed[20]) const
	{
		memcpy(seed, seed_, 20);
	}

	bool is_continue() const
	{
		return continue_;
	}

private:
	virtual int decode_packet(const unsigned char *buf, size_t buflen);

private:
	std::string auth_plugin_name_;
	unsigned char seed_[20];
	bool continue_;

public:
	MySQLAuthResponse() : continue_(false) { }
	//move constructor
	MySQLAuthResponse(MySQLAuthResponse&& move) = default;
	//move operator
	MySQLAuthResponse& operator= (MySQLAuthResponse&& move) = default;
};

class MySQLAuthSwitchRequest : public MySQLRequest
{
public:
	void set_password(std::string password)
	{
		password_ = std::move(password);
	}

	void set_auth_plugin_name(std::string name)
	{
		auth_plugin_name_ = std::move(name);
	}

	void set_seed(const unsigned char seed[20])
	{
		memcpy(seed_, seed, 20);
	}

private:
	virtual int encode(struct iovec vectors[], int max);

	/* Not implemented. */
	virtual int decode_packet(const unsigned char *buf, size_t buflen)
	{
		return -2;
	}

	std::string password_;
	std::string auth_plugin_name_;
	unsigned char seed_[20];

public:
	MySQLAuthSwitchRequest() { }
	//move constructor
	MySQLAuthSwitchRequest(MySQLAuthSwitchRequest&& move) = default;
	//move operator
	MySQLAuthSwitchRequest& operator= (MySQLAuthSwitchRequest&& move) = default;
};

class MySQLPublicKeyRequest : public MySQLRequest
{
public:
	void set_caching_sha2() { byte_ = 0x02; }
	void set_sha256() { byte_ = 0x01; }

private:
	virtual int encode(struct iovec vectors[], int max)
	{
		buf_.assign(&byte_, 1);
		return MySQLRequest::encode(vectors, max);
	}

	/* Not implemented. */
	virtual int decode_packet(const unsigned char *buf, size_t buflen)
	{
		return -2;
	}

	char byte_;

public:
	MySQLPublicKeyRequest() : byte_(0x01) { }
	//move constructor
	MySQLPublicKeyRequest(MySQLPublicKeyRequest&& move) = default;
	//move operator
	MySQLPublicKeyRequest& operator= (MySQLPublicKeyRequest&& move) = default;
};

class MySQLPublicKeyResponse : public MySQLResponse
{
public:
	std::string get_public_key() const
	{
		return public_key_;
	}

	void set_public_key(std::string key)
	{
		public_key_ = std::move(key);
	}

private:
	virtual int encode(struct iovec vectors[], int max);
	virtual int decode_packet(const unsigned char *buf, size_t buflen);

	std::string public_key_;

public:
	MySQLPublicKeyResponse() { }
	//move constructor
	MySQLPublicKeyResponse(MySQLPublicKeyResponse&& move) = default;
	//move operator
	MySQLPublicKeyResponse& operator= (MySQLPublicKeyResponse&& move) = default;
};

class MySQLRSAAuthRequest : public MySQLRequest
{
public:
	void set_password(std::string password)
	{
		password_ = std::move(password);
	}

	void set_public_key(std::string key)
	{
		public_key_ = std::move(key);
	}

	void set_seed(const unsigned char seed[20])
	{
		memcpy(seed_, seed, 20);
	}

private:
	virtual int encode(struct iovec vectors[], int max);

	/* Not implemented. */
	virtual int decode_packet(const unsigned char *buf, size_t buflen)
	{
		return -2;
	}

	int rsa_encrypt(void *ctx);

	std::string password_;
	std::string public_key_;
	unsigned char seed_[20];

public:
	MySQLRSAAuthRequest() { }
	//move constructor
	MySQLRSAAuthRequest(MySQLRSAAuthRequest&& move) = default;
	//move operator
	MySQLRSAAuthRequest& operator= (MySQLRSAAuthRequest&& move) = default;
};

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


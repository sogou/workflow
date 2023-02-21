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
#include <errno.h>
#include <string>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <utility>
#include "SSLWrapper.h"
#include "mysql_byteorder.h"
#include "mysql_types.h"
#include "MySQLResult.h"
#include "MySQLMessage.h"

namespace protocol
{

#define MYSQL_PAYLOAD_MAX	((1 << 24) - 1)

#define MYSQL_NATIVE_PASSWORD	"mysql_native_password"
#define CACHING_SHA2_PASSWORD	"caching_sha2_password"
#define MYSQL_CLEAR_PASSWORD	"mysql_clear_password"

MySQLMessage::~MySQLMessage()
{
	if (parser_)
	{
		mysql_parser_deinit(parser_);
		mysql_stream_deinit(stream_);
		delete parser_;
		delete stream_;
	}
}

MySQLMessage::MySQLMessage(MySQLMessage&& move) :
	ProtocolMessage(std::move(move))
{
	parser_ = move.parser_;
	stream_ = move.stream_;
	seqid_ = move.seqid_;
	cur_size_ = move.cur_size_;

	move.parser_ = NULL;
	move.stream_ = NULL;
	move.seqid_ = 0;
	move.cur_size_ = 0;
}

MySQLMessage& MySQLMessage::operator= (MySQLMessage&& move)
{
	if (this != &move)
	{
		*(ProtocolMessage *)this = std::move(move);

		if (parser_)
		{
			mysql_parser_deinit(parser_);
			mysql_stream_deinit(stream_);
			delete parser_;
			delete stream_;
		}

		parser_ = move.parser_;
		stream_ = move.stream_;
		seqid_ = move.seqid_;
		cur_size_ = move.cur_size_;

		move.parser_ = NULL;
		move.stream_ = NULL;
		move.seqid_ = 0;
		move.cur_size_ = 0;
	}

	return *this;
}

int MySQLMessage::append(const void *buf, size_t *size)
{
	const void *stream_buf;
	size_t stream_len;
	int ret;

	cur_size_ += *size;
	if (cur_size_ > this->size_limit)
	{
		errno = EMSGSIZE;
		return -1;
	}

	ret = mysql_stream_write(buf, *size, stream_);
	if (ret > 0)
	{
		seqid_ = mysql_stream_get_seq(stream_);
		mysql_stream_get_buf(&stream_buf, &stream_len, stream_);
		ret = decode_packet((const unsigned char *)stream_buf, stream_len);
		if (ret == -2)
		{
			errno = EBADMSG;
			ret = -1;
		}
	}

	return ret;
}

int MySQLMessage::encode(struct iovec vectors[], int max)
{
	const unsigned char *p = (unsigned char *)buf_.c_str();
	size_t nleft = buf_.size();
	uint8_t seqid_start = seqid_;
	uint8_t seqid = seqid_;
	unsigned char *head;
	uint32_t length;
	int i = 0;

	do
	{
		length = (nleft >= MYSQL_PAYLOAD_MAX ? MYSQL_PAYLOAD_MAX
											 : (uint32_t)nleft);
		head = heads_[seqid];
		int3store(head, length);
		head[3] = seqid++;
		vectors[i].iov_base = head;
		vectors[i].iov_len = 4;
		i++;
		vectors[i].iov_base = const_cast<unsigned char *>(p);
		vectors[i].iov_len = length;
		i++;

		if (i > max)//overflow
			break;

		if (nleft < MYSQL_PAYLOAD_MAX)
			return i;

		nleft -= MYSQL_PAYLOAD_MAX;
		p += length;
	} while (seqid != seqid_start);

	errno = EOVERFLOW;
	return -1;
}

void MySQLRequest::set_query(const char *query, size_t length)
{
	set_command(MYSQL_COM_QUERY);
	buf_.resize(length + 1);
	char *buffer = const_cast<char *>(buf_.c_str());

	buffer[0] = MYSQL_COM_QUERY;
	if (length > 0)
		memcpy(buffer + 1, query, length);
}

std::string MySQLRequest::get_query() const
{
	size_t len = buf_.size();
	if (len <= 1 || buf_[0] != MYSQL_COM_QUERY)
		return "";

	return std::string(buf_.c_str() + 1);
}

#define MYSQL_CAPFLAG_CLIENT_SSL				0x00000800
#define MYSQL_CAPFLAG_CLIENT_PROTOCOL_41		0x00000200
#define MYSQL_CAPFLAG_CLIENT_SECURE_CONNECTION	0x00008000
#define MYSQL_CAPFLAG_CLIENT_CONNECT_WITH_DB	0x00000008
#define MYSQL_CAPFLAG_CLIENT_MULTI_STATEMENTS	0x00010000
#define MYSQL_CAPFLAG_CLIENT_MULTI_RESULTS		0x00020000
#define MYSQL_CAPFLAG_CLIENT_PS_MULTI_RESULTS	0x00040000
#define MYSQL_CAPFLAG_CLIENT_PLUGIN_AUTH		0x00080000
#define MYSQL_CAPFLAG_CLIENT_LOCAL_FILES		0x00000080

int MySQLHandshakeResponse::encode(struct iovec vectors[], int max)
{
	const char empty[10] = {0};
	uint16_t cap_flags_lower = capability_flags_ & 0xffffffff;
	uint16_t cap_flags_upper = capability_flags_ >> 16;

	buf_.clear();
	buf_.append((const char *)&protocol_version_, 1);
	buf_.append(server_version_.c_str(), server_version_.size() + 1);
	buf_.append((const char *)&connection_id_, 4);
	buf_.append((const char *)auth_plugin_data_, 8);
	buf_.append(empty, 1);
	buf_.append((const char *)&cap_flags_lower, 2);
	buf_.append((const char *)&character_set_, 1);
	buf_.append((const char *)&status_flags_, 2);
	buf_.append((const char *)&cap_flags_upper, 2);
	buf_.push_back(21);
	buf_.append(empty, 10);
	buf_.append((const char *)auth_plugin_data_ + 8, 12);
	buf_.push_back(0);
	if (capability_flags_ & MYSQL_CAPFLAG_CLIENT_PLUGIN_AUTH)
		buf_.append(MYSQL_NATIVE_PASSWORD, strlen(MYSQL_NATIVE_PASSWORD) + 1);

	return MySQLMessage::encode(vectors, max);
}

int MySQLHandshakeResponse::decode_packet(const unsigned char *buf, size_t buflen)
{
	const unsigned char *end = buf + buflen;
	const unsigned char *pos;
	uint16_t cap_flags_lower;
	uint16_t cap_flags_upper;

	if (buflen == 0)
		return -2;

	protocol_version_ = *buf;
	if (protocol_version_ == 255)
	{
		if (buflen >= 4)
		{
			const_cast<unsigned char *>(buf)[3] = '#';
			if (mysql_parser_parse(buf, buflen, parser_) == 1)
			{
				disallowed_ = true;
				return 1;
			}
		}

		errno = EBADMSG;
		return -1;
	}

	pos = ++buf;
	while (pos < end && *pos)
		pos++;

	if (pos >= end || end - pos < 45)
		return -2;

	server_version_.assign((const char *)buf, pos - buf);
	buf = pos + 1;

	connection_id_ = uint4korr(buf);
	buf += 4;
	memcpy(auth_plugin_data_, buf, 8);
	buf += 9;
	cap_flags_lower = uint2korr(buf);
	buf += 2;
	character_set_ = *buf++;
	status_flags_ = uint2korr(buf);
	buf += 2;
	cap_flags_upper = uint2korr(buf);
	buf += 2;
	capability_flags_ = (cap_flags_upper << 16U) + cap_flags_lower;
	auth_plugin_data_len_ = *buf++;
	// 10 bytes reserved. All 0s.
	buf += 10;
	// auth_plugin_data always 20 bytes
	if (auth_plugin_data_len_ > 21)
		return -2;

	memcpy(auth_plugin_data_ + 8, buf, 12);
	buf += 13;
	if (capability_flags_ & MYSQL_CAPFLAG_CLIENT_PLUGIN_AUTH)
	{
		if (buf == end || *(end - 1) != '\0')
			return -2;

		auth_plugin_name_.assign((const char *)buf, end - 1 - buf);
	}

	return 1;
}

static std::string __native_password_encrypt(const std::string& password,
											 unsigned char seed[20])
{
	unsigned char buf1[20];
	unsigned char buf2[40];
	int i;

	// SHA1( password ) ^ SHA1( seed + SHA1( SHA1( password ) ) )
	SHA1((unsigned char *)password.c_str(), password.size(), buf1);
	SHA1(buf1, 20, buf2 + 20);
	memcpy(buf2, seed, 20);
	SHA1(buf2, 40, buf2);
	for (i = 0; i < 20; i++)
		buf1[i] ^= buf2[i];

	return std::string((const char *)buf1, 20);
}

static std::string __caching_sha2_password_encrypt(const std::string& password,
												   unsigned char seed[20])
{
	unsigned char buf1[32];
	unsigned char buf2[52];
	int i;

	// SHA256( password ) ^ SHA256( SHA256( SHA256( password ) ) + seed)
	SHA256((unsigned char *)password.c_str(), password.size(), buf1);
	SHA256(buf1, 32, buf2);
	memcpy(buf2 + 32, seed, 20);
	SHA256(buf2, 52, buf2);
	for (i = 0; i < 32; i++)
		buf1[i] ^= buf2[i];

	return std::string((const char *)buf1, 32);
}

int MySQLSSLRequest::encode(struct iovec vectors[], int max)
{
	unsigned char header[32] = {0};
	unsigned char *pos = header;
	int ret;

	int4store(pos, MYSQL_CAPFLAG_CLIENT_SSL |
				   MYSQL_CAPFLAG_CLIENT_PROTOCOL_41 |
				   MYSQL_CAPFLAG_CLIENT_SECURE_CONNECTION |
				   MYSQL_CAPFLAG_CLIENT_CONNECT_WITH_DB |
				   MYSQL_CAPFLAG_CLIENT_MULTI_RESULTS|
				   MYSQL_CAPFLAG_CLIENT_LOCAL_FILES |
				   MYSQL_CAPFLAG_CLIENT_MULTI_STATEMENTS |
				   MYSQL_CAPFLAG_CLIENT_PS_MULTI_RESULTS |
				   MYSQL_CAPFLAG_CLIENT_PLUGIN_AUTH);
	pos += 4;
	int4store(pos, 0);
	pos += 4;
	*pos = (uint8_t)character_set_;

	buf_.clear();
	buf_.append((char *)header, 32);
	ret = MySQLMessage::encode(vectors, max);
	if (ret >= 0)
	{
		max -= ret;
		if (max >= 8) /* Indeed SSL handshaker needs only 1 vector. */
		{
			max = ssl_handshaker_.encode(vectors + ret, max);
			if (max >= 0)
				return max + ret;
		}
		else
			errno = EOVERFLOW;
	}

	return -1;
}

int MySQLAuthRequest::encode(struct iovec vectors[], int max)
{
	unsigned char header[32] = {0};
	unsigned char *pos = header;
	std::string str;

	int4store(pos, MYSQL_CAPFLAG_CLIENT_PROTOCOL_41 |
				   MYSQL_CAPFLAG_CLIENT_SECURE_CONNECTION |
				   MYSQL_CAPFLAG_CLIENT_CONNECT_WITH_DB |
				   MYSQL_CAPFLAG_CLIENT_MULTI_RESULTS|
				   MYSQL_CAPFLAG_CLIENT_LOCAL_FILES |
				   MYSQL_CAPFLAG_CLIENT_MULTI_STATEMENTS |
				   MYSQL_CAPFLAG_CLIENT_PS_MULTI_RESULTS |
				   MYSQL_CAPFLAG_CLIENT_PLUGIN_AUTH);
	pos += 4;
	int4store(pos, 0);
	pos += 4;
	*pos = (uint8_t)character_set_;

	if (password_.empty())
		str.push_back(0);
	else if (auth_plugin_name_ == CACHING_SHA2_PASSWORD)
	{
		str.push_back(32);
		str += __caching_sha2_password_encrypt(password_, seed_);
	}
	else
	{
		str.push_back(20);
		str += __native_password_encrypt(password_, seed_);
	}

	buf_.clear();
	buf_.append((char *)header, 32);
	buf_.append(username_.c_str(), username_.size() + 1);
	buf_.append(str);
	buf_.append(db_.c_str(), db_.size() + 1);
	if (auth_plugin_name_.size() != 0)
		buf_.append(auth_plugin_name_.c_str(), auth_plugin_name_.size() + 1);

	return MySQLMessage::encode(vectors, max);
}

int MySQLAuthRequest::decode_packet(const unsigned char *buf, size_t buflen)
{
	const unsigned char *end = buf + buflen;
	const unsigned char *pos;

	if (buflen < 32)
		return -2;

	uint32_t flags = uint4korr(buf);

	if (!(flags & MYSQL_CAPFLAG_CLIENT_PROTOCOL_41))
		return -2;

	buf += 8;
	character_set_ = *buf++;
	buf += 23;

	pos = buf;
	while (pos < end && *pos)
		pos++;

	if (pos >= end)
		return -2;

	username_.assign((const char *)buf, pos - buf);
	buf = pos + 1;

	return 1;
}

int MySQLAuthResponse::decode_packet(const unsigned char *buf, size_t buflen)
{
	const unsigned char *end = buf + buflen;
	const unsigned char *pos;
	const unsigned char *str;
	unsigned long long len;
	int ret;

	if (end == buf)
		return -2;

	switch (*buf)
	{
	case 0x00:
	case 0xff:
		return MySQLResponse::decode_packet(buf, buflen);

	case 0xfe:
		pos = ++buf;
		while (pos < end && *pos)
			pos++;

		if (pos >= end)
			return -2;

		auth_plugin_name_.assign((const char *)buf, pos - buf);
		buf = pos + 1;
		if (buf == end || *(end - 1) != '\0')
			return -2;

		if (end - 1 - buf != 20)
			return -2;

		memcpy(seed_, buf, 20);
		return 1;

	default:
		pos = buf;
		ret = decode_string(&str, &len, &pos, end);
		if (ret <= 0)
			return ret;

		if (len == 1)
		{
			if (*str == 0x03)
			{
				if (end > pos)
					return MySQLResponse::decode_packet(pos, end - pos);
				else
					return 0;
			}
			else if (*str == 0x04)
			{
				continue_ = true;
				return 1;
			}
		}

		return -2;
	}
}

int MySQLAuthSwitchRequest::encode(struct iovec vectors[], int max)
{
	if (password_.empty())
	{
		buf_ = "\0";
	}
	else if (auth_plugin_name_ == MYSQL_NATIVE_PASSWORD)
	{
		buf_ = __native_password_encrypt(password_, seed_);
	}
	else if (auth_plugin_name_ == CACHING_SHA2_PASSWORD)
	{
		buf_ = __caching_sha2_password_encrypt(password_, seed_);
	}
	else if (auth_plugin_name_ == MYSQL_CLEAR_PASSWORD)
	{
		buf_ = password_;
		buf_.push_back('\0');
	}
	else
	{
		errno = EINVAL;
		return -1;
	}

	return MySQLMessage::encode(vectors, max);
}

int MySQLPublicKeyResponse::decode_packet(const unsigned char *buf,
										  size_t buflen)
{
	if (buflen == 0 || *buf != 0x01)
		return -2;

	if (buflen == 1)
		return 0;

	public_key_.assign((const char *)buf + 1, buflen - 1);
	return 1;
}

int MySQLPublicKeyResponse::encode(struct iovec vectors[], int max)
{
	buf_.clear();
	buf_.push_back(0x01);
	buf_ += public_key_;
	return MySQLMessage::encode(vectors, max);
}

int MySQLRSAAuthRequest::rsa_encrypt(void *ctx)
{
	EVP_PKEY_CTX *pkey_ctx = (EVP_PKEY_CTX *)ctx;
	unsigned char out[256];
	size_t outlen = 256;
	std::string pass;
	unsigned char *p;
	size_t i;

	if (EVP_PKEY_encrypt_init(pkey_ctx) > 0 &&
		EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_OAEP_PADDING) > 0)
	{
		pass.reserve(password_.size() + 1);
		p = (unsigned char *)pass.c_str();
		for (i = 0; i <= password_.size(); i++)
			p[i] = (unsigned char)password_[i] ^ seed_[i % 20];

		if (EVP_PKEY_encrypt(pkey_ctx, out, &outlen, p, i) > 0)
		{
			buf_.assign((char *)out, 256);
			return 0;
		}
	}

	return -1;
}

int MySQLRSAAuthRequest::encode(struct iovec vectors[], int max)
{
	BIO *bio;
	EVP_PKEY *pkey;
	EVP_PKEY_CTX *pkey_ctx;
	int ret = -1;

	bio = BIO_new_mem_buf(public_key_.c_str(), public_key_.size());
	if (bio)
	{
		pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
		if (pkey)
		{
			pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
			if (pkey_ctx)
			{
				ret = rsa_encrypt(pkey_ctx);
				EVP_PKEY_CTX_free(pkey_ctx);
			}

			EVP_PKEY_free(pkey);
		}

		BIO_free(bio);
	}

	if (ret < 0)
		return ret;

	return MySQLMessage::encode(vectors, max);
}

void MySQLResponse::set_ok_packet()
{
	uint16_t zero16 = 0;
	buf_.clear();
	buf_.push_back(0x00);
	buf_.append((const char *)&zero16, 2);
	buf_.append((const char *)&zero16, 2);
	buf_.append((const char *)&zero16, 2);
}

int MySQLResponse::decode_packet(const unsigned char *buf, size_t buflen)
{
	return mysql_parser_parse(buf, buflen, parser_);
}

unsigned long long MySQLResponse::get_affected_rows() const
{
	unsigned long long affected_rows = 0;
	MySQLResultCursor cursor(this);

	do {
		affected_rows += cursor.get_affected_rows();
	} while (cursor.next_result_set());

	return affected_rows;
}

// return array api
unsigned long long MySQLResponse::get_last_insert_id() const
{
	unsigned long long insert_id = 0;
	MySQLResultCursor cursor(this);

	do {
		if (cursor.get_insert_id())
			insert_id = cursor.get_insert_id();
	} while (cursor.next_result_set());

	return insert_id;
}

int MySQLResponse::get_warnings() const
{
	int warning_count = 0;
	MySQLResultCursor cursor(this);

	do {
		warning_count += cursor.get_warnings();
	} while (cursor.next_result_set());

	return warning_count;
}

std::string MySQLResponse::get_info() const
{
	std::string info;
	MySQLResultCursor cursor(this);

	do {
		if (info.length() > 0)
			info += " ";
		info += cursor.get_info();
	} while (cursor.next_result_set());

	return info;
}

bool MySQLResponse::is_ok_packet() const
{
	return parser_->packet_type == MYSQL_PACKET_OK;
}

bool MySQLResponse::is_error_packet() const
{
	return parser_->packet_type == MYSQL_PACKET_ERROR;
}

}


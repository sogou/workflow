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
           Li Yingxin (liyingxin@sogou-inc.com)
*/

#include <stdio.h>
#include <string.h>
#include <string>
#include <unordered_map>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "WFTaskError.h"
#include "WFTaskFactory.h"
#include "MySQLMessage.h"
#include "StringUtil.h"
#include "mysql_types.h"

using namespace protocol;

#define MYSQL_KEEPALIVE_DEFAULT		(60 * 1000)
#define MYSQL_KEEPALIVE_TRANSACTION	(3600 * 1000)

/**********Client**********/

class ComplexMySQLTask : public WFComplexClientTask<MySQLRequest, MySQLResponse>
{
protected:
	virtual bool check_request();
	virtual CommMessageOut *message_out();
	virtual CommMessageIn *message_in();
	virtual int keep_alive_timeout();
	virtual bool init_success();
	virtual bool finish_once();

protected:
	virtual WFConnection *get_connection() const
	{
		WFConnection *conn = this->WFComplexClientTask::get_connection();

		if (conn && is_ssl_)
			return (SSLConnection *)conn->get_context();

		return conn;
	}

private:
	struct SSLConnection : public WFConnection
	{
		SSL *ssl_;
		SSLWrapper wrapper_;
		SSLConnection(SSL *ssl) : wrapper_(&wrapper_, ssl)
		{
			ssl_ = ssl;
		}
	};

	SSL *get_ssl() const
	{
		return ((SSLConnection *)this->get_connection())->ssl_;
	}

	SSLWrapper *get_ssl_wrapper(ProtocolMessage *msg) const
	{
		SSLConnection *conn = (SSLConnection *)this->get_connection();
		conn->wrapper_ = SSLWrapper(msg, conn->ssl_);
		return &conn->wrapper_;
	}

	int init_ssl_connection();

	struct MySSLWrapper : public SSLWrapper
	{
		MySSLWrapper(ProtocolMessage *msg, SSL *ssl) :
			SSLWrapper(msg, ssl)
		{ }
		ProtocolMessage *get_msg() const { return this->msg; }
		virtual ~MySSLWrapper() { delete this->msg; }
	};

private:
	struct handshake_ctx
	{
		char challenge[20];
		unsigned char mysql_seqid;
	};

private:
	std::string username_;
	std::string password_;
	std::string db_;
	std::string res_charset_;
	short character_set_;
	short state_;
	int error_;
	bool is_ssl_;
	bool is_user_request_;

public:
	ComplexMySQLTask(int retry_max, mysql_callback_t&& callback):
		WFComplexClientTask(retry_max, std::move(callback)),
		character_set_(33),
		is_user_request_(true)
	{}
};

bool ComplexMySQLTask::check_request()
{
	if (this->req.query_is_unset() == false)
	{
		if (this->req.get_command() == MYSQL_COM_QUERY)
		{
			std::string query = this->req.get_query();

			if (strncasecmp(query.c_str(), "USE ", 4) &&
				strncasecmp(query.c_str(), "SET NAMES ", 10) &&
				strncasecmp(query.c_str(), "SET CHARSET ", 12) &&
				strncasecmp(query.c_str(), "SET CHARACTER SET ", 18))
			{
				return true;
			}
		}

		this->error = WFT_ERR_MYSQL_COMMAND_DISALLOWED;
	}
	else
		this->error = WFT_ERR_MYSQL_QUERY_NOT_SET;

	this->state = WFT_STATE_TASK_ERROR;
	return false;
}

static SSL *__create_ssl(SSL_CTX *ssl_ctx)
{
	BIO *wbio;
	BIO *rbio;
	SSL *ssl;

	rbio = BIO_new(BIO_s_mem());
	if (rbio)
	{
		wbio = BIO_new(BIO_s_mem());
		if (wbio)
		{
			ssl = SSL_new(ssl_ctx);
			if (ssl)
			{
				SSL_set_bio(ssl, rbio, wbio);
				return ssl;
			}

			BIO_free(wbio);
		}

		BIO_free(rbio);
	}

	return NULL;
}

int ComplexMySQLTask::init_ssl_connection()
{
	SSL *ssl = __create_ssl(WFGlobal::get_ssl_client_ctx());
	WFConnection *conn;

	if (!ssl)
		return -1;

	SSL_set_connect_state(ssl);

	conn = this->WFComplexClientTask::get_connection();
	SSLConnection *ssl_conn = new SSLConnection(ssl);

	auto&& deleter = [] (void *ctx)
	{
		SSLConnection *ssl_conn = (SSLConnection *)ctx;
		SSL_free(ssl_conn->ssl_);
		delete ssl_conn;
	};
	conn->set_context(ssl_conn, std::move(deleter));
	return 0;
}

CommMessageOut *ComplexMySQLTask::message_out()
{
	long long seqid = this->get_seq();

	is_user_request_ = false;
	if (seqid == 0)
		return new MySQLHandshakeRequest;

	if (is_ssl_)
	{
		if (seqid == 1)
		{
			auto *req = new MySQLSSLRequest(character_set_, get_ssl());
			auto *conn = this->get_connection();
			auto *ctx = (struct handshake_ctx *)conn->get_context();

			req->set_seqid(ctx->mysql_seqid++);
			return req;
		}

		seqid--;
	}

	if (seqid == 1)
	{
		auto *req = new MySQLAuthRequest;
		auto *conn = this->get_connection();
		auto *ctx = (struct handshake_ctx *)conn->get_context();

		req->set_seqid(ctx->mysql_seqid++);
		req->set_challenge(ctx->challenge);
		delete ctx;
		conn->set_context(NULL, nullptr);
		req->set_auth(username_, password_, db_, character_set_);
		if (is_ssl_)
			return new MySSLWrapper(req, get_ssl());
		else
			return req;
	}
	else if (seqid == 2 && res_charset_.size() != 0)
	{
		auto *req = new MySQLRequest;
		req->set_query("SET NAMES " + res_charset_);
		if (is_ssl_)
			return new MySSLWrapper(req, get_ssl());
		else
			return req;
	}

	is_user_request_ = true;
	if (this->is_fixed_addr())
	{
		auto *target = (RouteManager::RouteTarget *)this->get_target();

		/* If it's a transaction task, generate a ECONNRESET error when
		 * the target was reconnected. */
		if (seqid <= 3 && (seqid == 2 || res_charset_.size() != 0))
		{
			if (target->state)
			{
				errno = ECONNRESET;
				return NULL;
			}
			else
				target->state = 1;
		}
	}

	auto *msg = (ProtocolMessage *)this->WFComplexClientTask::message_out();
	return is_ssl_ ? get_ssl_wrapper(msg) : msg;
}

CommMessageIn *ComplexMySQLTask::message_in()
{
	long long seqid = this->get_seq();
	ProtocolMessage *resp;

	if (seqid == 0)
		return new MySQLHandshakeResponse;

	if (is_ssl_)
	{
		if (seqid == 1)
			return new SSLHandshaker(get_ssl());

		seqid--;
	}

	if (seqid == 1)
		resp = new MySQLAuthResponse;
	else if (seqid == 2 && !is_user_request_)
		resp = new MySQLResponse;
	else
		resp = (ProtocolMessage *)this->WFComplexClientTask::message_in();

	if (!is_ssl_)
		return resp;

	if (is_user_request_)
		return get_ssl_wrapper(resp);
	else
		return new MySSLWrapper(resp, get_ssl());
}

int ComplexMySQLTask::keep_alive_timeout()
{
	long long seqid = this->get_seq();

	state_ = WFT_STATE_SUCCESS;
	error_ = 0;
	if (seqid == 0)
	{
		auto *resp = (MySQLHandshakeResponse *)this->get_message_in();

		if (resp->host_disallowed())
		{
			this->resp = std::move(*(MySQLResponse *)resp);
			state_ = WFT_STATE_TASK_ERROR;
			error_ = WFT_ERR_MYSQL_HOST_NOT_ALLOWED;
			return 0;
		}

		if (is_ssl_)
		{
			if (!(resp->get_capability_flags() & 0x800))
			{
				this->resp = std::move(*(MySQLResponse *)resp);
				state_ = WFT_STATE_TASK_ERROR;
				error_ = WFT_ERR_MYSQL_SSL_NOT_SUPPORTED;
				return 0;
			}

			if (init_ssl_connection() < 0)
			{
				state_ = WFT_STATE_SYS_ERROR;
				error_ = errno;
				return 0;
			}
		}

		auto *ctx = new handshake_ctx();
		auto *conn = this->get_connection();

		ctx->mysql_seqid = resp->get_seqid() + 1;
		resp->get_challenge(ctx->challenge);
		conn->set_context(ctx, [](void *ctx) {
			delete (handshake_ctx *)ctx;
		});
	}
	else if (!is_user_request_)
	{
		if (!is_ssl_ || seqid != 1)
		{
			auto *msg = (ProtocolMessage *)this->get_message_in();
			MySQLResponse *resp;
	
			if (is_ssl_)
				resp = (MySQLResponse *)((MySSLWrapper *)msg)->get_msg();
			else
				resp = (MySQLResponse *)msg;

			if (!resp->is_ok_packet())
			{
				this->resp = std::move(*resp);

				if (is_ssl_)
					seqid--;

				state_ = WFT_STATE_TASK_ERROR;
				if (seqid == 1)
					error_ = WFT_ERR_MYSQL_ACCESS_DENIED;
				else
					error_ = WFT_ERR_MYSQL_INVALID_CHARACTER_SET;
			}
		}
	}
	else
		return this->keep_alive_timeo;

	return MYSQL_KEEPALIVE_DEFAULT;
}

/*
+--------------------+---------------------+-----+
| CHARACTER_SET_NAME | COLLATION_NAME      | ID  |
+--------------------+---------------------+-----+
| big5               | big5_chinese_ci     |   1 |
| dec8               | dec8_swedish_ci     |   3 |
| cp850              | cp850_general_ci    |   4 |
| hp8                | hp8_english_ci      |   6 |
| koi8r              | koi8r_general_ci    |   7 |
| latin1             | latin1_swedish_ci   |   8 |
| latin2             | latin2_general_ci   |   9 |
| swe7               | swe7_swedish_ci     |  10 |
| ascii              | ascii_general_ci    |  11 |
| ujis               | ujis_japanese_ci    |  12 |
| sjis               | sjis_japanese_ci    |  13 |
| hebrew             | hebrew_general_ci   |  16 |
| tis620             | tis620_thai_ci      |  18 |
| euckr              | euckr_korean_ci     |  19 |
| koi8u              | koi8u_general_ci    |  22 |
| gb2312             | gb2312_chinese_ci   |  24 |
| greek              | greek_general_ci    |  25 |
| cp1250             | cp1250_general_ci   |  26 |
| gbk                | gbk_chinese_ci      |  28 |
| latin5             | latin5_turkish_ci   |  30 |
| armscii8           | armscii8_general_ci |  32 |
| utf8               | utf8_general_ci     |  33 |
| ucs2               | ucs2_general_ci     |  35 |
| cp866              | cp866_general_ci    |  36 |
| keybcs2            | keybcs2_general_ci  |  37 |
| macce              | macce_general_ci    |  38 |
| macroman           | macroman_general_ci |  39 |
| cp852              | cp852_general_ci    |  40 |
| latin7             | latin7_general_ci   |  41 |
| cp1251             | cp1251_general_ci   |  51 |
| utf16              | utf16_general_ci    |  54 |
| utf16le            | utf16le_general_ci  |  56 |
| cp1256             | cp1256_general_ci   |  57 |
| cp1257             | cp1257_general_ci   |  59 |
| utf32              | utf32_general_ci    |  60 |
| binary             | binary              |  63 |
| geostd8            | geostd8_general_ci  |  92 |
| cp932              | cp932_japanese_ci   |  95 |
| eucjpms            | eucjpms_japanese_ci |  97 |
| gb18030            | gb18030_chinese_ci  | 248 |
| utf8mb4            | utf8mb4_0900_ai_ci  | 255 |
+--------------------+---------------------+-----+
*/

static int __mysql_get_character_set(const std::string& charset)
{
	static std::unordered_map<std::string, int> charset_map = {
		{"big5",	1},
		{"dec8",	3},
		{"cp850",	4},
		{"hp8",		5},
		{"koi8r",	6},
		{"latin1",	7},
		{"latin2",	8},
		{"swe7",	10},
		{"ascii",	11},
		{"ujis",	12},
		{"sjis",	13},
		{"hebrew",	16},
		{"tis620",	18},
		{"euckr",	19},
		{"koi8u",	22},
		{"gb2312",	24},
		{"greek",	25},
		{"cp1250",	26},
		{"gbk",		28},
		{"latin5",	30},
		{"armscii8",32},
		{"utf8",	33},
		{"ucs2",	35},
		{"cp866",	36},
		{"keybcs2",	37},
		{"macce",	38},
		{"macroman",39},
		{"cp852",	40},
		{"latin7",	41},
		{"cp1251",	51},
		{"utf16",	54},
		{"utf16le",	56},
		{"cp1256",	57},
		{"cp1257",	59},
		{"utf32",	60},
		{"binary",	63},
		{"geostd8",	92},
		{"cp932",	95},
		{"eucjpms",	97},
		{"gb18030",	248},
		{"utf8mb4",	255},
	};

	const auto it = charset_map.find(charset);

	if (it != charset_map.cend())
		return it->second;

	return -1;
}

bool ComplexMySQLTask::init_success()
{
	if (uri_.scheme && strcasecmp(uri_.scheme, "mysql") == 0)
		is_ssl_ = false;
	else if (uri_.scheme && strcasecmp(uri_.scheme, "mysqls") == 0)
		is_ssl_ = true;
	else
	{
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_URI_SCHEME_INVALID;
		return false;
	}

	//todo mysql+unix
	username_.clear();
	password_.clear();
	db_.clear();
	if (uri_.userinfo)
	{
		const char *colon = NULL;
		const char *pos = uri_.userinfo;

		while (*pos && *pos != ':')
			pos++;

		if (*pos == ':')
			colon = pos++;

		if (colon)
		{
			if (colon > uri_.userinfo)
			{
				username_.assign(uri_.userinfo, colon - uri_.userinfo);
				StringUtil::url_decode(username_);
			}

			if (*pos)
			{
				password_.assign(pos);
				StringUtil::url_decode(password_);
			}
		}
		else
		{
			username_.assign(uri_.userinfo);
			StringUtil::url_decode(username_);
		}
	}

	if (uri_.path && uri_.path[0] == '/' && uri_.path[1])
	{
		db_.assign(uri_.path + 1);
		StringUtil::url_decode(db_);
	}

	std::string transaction;

	if (uri_.query)
	{
		auto query_kv = URIParser::split_query(uri_.query);

		for (auto& kv : query_kv)
		{
			if (strcasecmp(kv.first.c_str(), "transaction") == 0)
				transaction = std::move(kv.second);
			else if (strcasecmp(kv.first.c_str(), "character_set") == 0)
			{
				character_set_ = __mysql_get_character_set(kv.second);
				if (character_set_ < 0)
				{
					this->state = WFT_STATE_TASK_ERROR;
					this->error = WFT_ERR_MYSQL_INVALID_CHARACTER_SET;
					return false;
				}
			}
			else if (strcasecmp(kv.first.c_str(), "character_set_results") == 0)
				res_charset_ = std::move(kv.second);
		}
	}

	size_t info_len = username_.size() + password_.size() + db_.size() +
					  res_charset_.size() + 50;
	char *info = new char[info_len];

	snprintf(info, info_len, "%s|user:%s|pass:%s|db:%s|"
							 "charset:%d|rcharset:%s",
			 is_ssl_ ? "mysqls" : "mysql", username_.c_str(), password_.c_str(),
			 db_.c_str(), character_set_, res_charset_.c_str());
	this->WFComplexClientTask::set_transport_type(TT_TCP);

	if (!transaction.empty())
	{
		this->WFComplexClientTask::set_info(std::string("?maxconn=1&") +
											info + "|txn:" + transaction);
		this->set_fixed_addr(true);
	}
	else
		this->WFComplexClientTask::set_info(info);

	delete []info;
	return true;
}

bool ComplexMySQLTask::finish_once()
{
	if (!is_user_request_)
	{
		delete this->get_message_out();
		delete this->get_message_in();

		if (this->state == WFT_STATE_SUCCESS && state_ != WFT_STATE_SUCCESS)
		{
			this->state = state_;
			this->error = error_;
			this->disable_retry();
		}

		is_user_request_ = true;
		return false;
	}

	if (this->is_fixed_addr())
	{
		if (this->state != WFT_STATE_SUCCESS || this->keep_alive_timeo == 0)
		{
			auto *target = (RouteManager::RouteTarget *)this->get_target();
			if (target)
				target->state = 0;
		}
	}

	return true;
}

/**********Client Factory**********/

// mysql://user:password@host:port/db_name
// url = "mysql://admin:123456@192.168.1.101:3301/test"
// url = "mysql://127.0.0.1:3306"
WFMySQLTask *WFTaskFactory::create_mysql_task(const std::string& url,
											  int retry_max,
											  mysql_callback_t callback)
{
	auto *task = new ComplexMySQLTask(retry_max, std::move(callback));
	ParsedURI uri;

	URIParser::parse(url, uri);
	task->init(std::move(uri));
	if (task->is_fixed_addr())
		task->set_keep_alive(MYSQL_KEEPALIVE_TRANSACTION);
	else
		task->set_keep_alive(MYSQL_KEEPALIVE_DEFAULT);

	return task;
}

WFMySQLTask *WFTaskFactory::create_mysql_task(const ParsedURI& uri,
											  int retry_max,
											  mysql_callback_t callback)
{
	auto *task = new ComplexMySQLTask(retry_max, std::move(callback));

	task->init(uri);
	if (task->is_fixed_addr())
		task->set_keep_alive(MYSQL_KEEPALIVE_TRANSACTION);
	else
		task->set_keep_alive(MYSQL_KEEPALIVE_DEFAULT);

	return task;
}

/**********Server**********/

class WFMySQLServerTask : public WFServerTask<MySQLRequest, MySQLResponse>
{
public:
	WFMySQLServerTask(CommService *service,
					  std::function<void (WFMySQLTask *)>& process):
		WFServerTask(service, WFGlobal::get_scheduler(), process)
	{}

protected:
	virtual SubTask *done();
	virtual CommMessageOut *message_out();
	virtual CommMessageIn *message_in();
};

SubTask *WFMySQLServerTask::done()
{
	if (this->get_seq() == 0)
		delete this->get_message_in();

	return this->WFServerTask::done();
}

CommMessageOut *WFMySQLServerTask::message_out()
{
	long long seqid = this->get_seq();

	if (seqid == 0)
		this->resp.set_ok_packet();	// always success

	return this->WFServerTask::message_out();
}

CommMessageIn *WFMySQLServerTask::message_in()
{
	long long seqid = this->get_seq();

	if (seqid == 0)
		return new MySQLAuthRequest;

	return this->WFServerTask::message_in();
}

/**********Server Factory**********/

WFMySQLTask *WFServerTaskFactory::create_mysql_task(CommService *service,
							std::function<void (WFMySQLTask *)>& process)
{
	return new WFMySQLServerTask(service, process);
}


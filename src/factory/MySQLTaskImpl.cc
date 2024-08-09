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
           Li Yingxin (liyingxin@sogou-inc.com)
*/

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <string>
#include <unordered_map>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "WFTaskError.h"
#include "WFTaskFactory.h"
#include "StringUtil.h"
#include "WFGlobal.h"
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
	virtual int first_timeout();
	virtual bool init_success();
	virtual bool finish_once();

protected:
	virtual WFConnection *get_connection() const
	{
		WFConnection *conn = this->WFComplexClientTask::get_connection();

		if (conn)
		{
			void *ctx = conn->get_context();
			if (ctx)
				conn = (WFConnection *)ctx;
		}

		return conn;
	}

private:
	enum ConnState
	{
		ST_SSL_REQUEST,
		ST_AUTH_REQUEST,
		ST_AUTH_SWITCH_REQUEST,
		ST_CLEAR_PASSWORD_REQUEST,
		ST_SHA256_PUBLIC_KEY_REQUEST,
		ST_CSHA2_PUBLIC_KEY_REQUEST,
		ST_RSA_AUTH_REQUEST,
		ST_CHARSET_REQUEST,
		ST_FIRST_USER_REQUEST,
		ST_USER_REQUEST
	};

	struct MyConnection : public WFConnection
	{
		std::string str;	// shared by auth, auth_swich and rsa_auth requests
		unsigned char seed[20];
		enum ConnState state;
		unsigned char mysql_seqid;
		SSL *ssl;
		SSLWrapper wrapper;
		MyConnection(SSL *ssl) : wrapper(&wrapper, ssl)
		{
			this->ssl = ssl;
		}
	};

	int check_handshake(MySQLHandshakeResponse *resp);
	int auth_switch(MySQLAuthResponse *resp, MyConnection *conn);

	struct MySSLWrapper : public SSLWrapper
	{
		MySSLWrapper(ProtocolMessage *msg, SSL *ssl) :
			SSLWrapper(msg, ssl)
		{ }
		ProtocolMessage *get_msg() const { return this->message; }
		virtual ~MySSLWrapper() { delete this->message; }
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

CommMessageOut *ComplexMySQLTask::message_out()
{
	MySQLAuthSwitchRequest *auth_switch_req;
	MySQLRSAAuthRequest *rsa_auth_req;
	MySQLAuthRequest *auth_req;
	MySQLRequest *req;

	is_user_request_ = false;
	if (this->get_seq() == 0)
		return new MySQLHandshakeRequest;

	auto *conn = (MyConnection *)this->get_connection();
	switch (conn->state)
	{
	case ST_SSL_REQUEST:
		req = new MySQLSSLRequest(character_set_, conn->ssl);
		req->set_seqid(conn->mysql_seqid);
		return req;

	case ST_AUTH_REQUEST:
		req = new MySQLAuthRequest;
		auth_req = (MySQLAuthRequest *)req;
		auth_req->set_auth(username_, password_, db_, character_set_);
		auth_req->set_auth_plugin_name(std::move(conn->str));
		auth_req->set_seed(conn->seed);
		break;

	case ST_CLEAR_PASSWORD_REQUEST:
		conn->str = "mysql_clear_password";
	case ST_AUTH_SWITCH_REQUEST:
		req = new MySQLAuthSwitchRequest;
		auth_switch_req = (MySQLAuthSwitchRequest *)req;
		auth_switch_req->set_password(password_);
		auth_switch_req->set_auth_plugin_name(std::move(conn->str));
		auth_switch_req->set_seed(conn->seed);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		WFGlobal::get_ssl_client_ctx();
#endif
		break;

	case ST_SHA256_PUBLIC_KEY_REQUEST:
		req = new MySQLPublicKeyRequest;
		((MySQLPublicKeyRequest *)req)->set_sha256();
		break;

	case ST_CSHA2_PUBLIC_KEY_REQUEST:
		req = new MySQLPublicKeyRequest;
		((MySQLPublicKeyRequest *)req)->set_caching_sha2();
		break;

	case ST_RSA_AUTH_REQUEST:
		req = new MySQLRSAAuthRequest;
		rsa_auth_req = (MySQLRSAAuthRequest *)req;
		rsa_auth_req->set_password(password_);
		rsa_auth_req->set_public_key(std::move(conn->str));
		rsa_auth_req->set_seed(conn->seed);
		break;

	case ST_CHARSET_REQUEST:
		req = new MySQLRequest;
		req->set_query("SET NAMES " + res_charset_);
		break;

	case ST_FIRST_USER_REQUEST:
		if (this->is_fixed_conn())
		{
			auto *target = (RouteManager::RouteTarget *)this->target;

			/* If it's a transaction task, generate a ECONNRESET error when
			 * the target was reconnected. */
			if (target->state)
			{
				is_user_request_ = true;
				errno = ECONNRESET;
				return NULL;
			}

			target->state = 1;
		}

	case ST_USER_REQUEST:
		is_user_request_ = true;
		req = (MySQLRequest *)this->WFComplexClientTask::message_out();
		break;

	default:
		assert(0);
		return NULL;
	}

	if (!is_user_request_ && conn->state != ST_CHARSET_REQUEST)
		req->set_seqid(conn->mysql_seqid);

	if (!is_ssl_)
		return req;

	if (is_user_request_)
	{
		conn->wrapper = SSLWrapper(req, conn->ssl);
		return &conn->wrapper;
	}
	else
		return new MySSLWrapper(req, conn->ssl);
}

CommMessageIn *ComplexMySQLTask::message_in()
{
	MySQLResponse *resp;

	if (this->get_seq() == 0)
		return new MySQLHandshakeResponse;

	auto *conn = (MyConnection *)this->get_connection();
	switch (conn->state)
	{
	case ST_SSL_REQUEST:
		return new SSLHandshaker(conn->ssl);

	case ST_AUTH_REQUEST:
	case ST_AUTH_SWITCH_REQUEST:
		resp = new MySQLAuthResponse;
		break;

	case ST_CLEAR_PASSWORD_REQUEST:
	case ST_RSA_AUTH_REQUEST:
		resp = new MySQLResponse;
		break;

	case ST_SHA256_PUBLIC_KEY_REQUEST:
	case ST_CSHA2_PUBLIC_KEY_REQUEST:
		resp = new MySQLPublicKeyResponse;
		break;

	case ST_CHARSET_REQUEST:
		resp = new MySQLResponse;
		break;

	case ST_FIRST_USER_REQUEST:
	case ST_USER_REQUEST:
		resp = (MySQLResponse *)this->WFComplexClientTask::message_in();
		break;

	default:
		assert(0);
		return NULL;
	}

	if (!is_ssl_)
		return resp;

	if (is_user_request_)
	{
		conn->wrapper = SSLWrapper(resp, conn->ssl);
		return &conn->wrapper;
	}
	else
		return new MySSLWrapper(resp, conn->ssl);
}

int ComplexMySQLTask::check_handshake(MySQLHandshakeResponse *resp)
{
	SSL *ssl = NULL;

	if (resp->host_disallowed())
	{
		this->resp = std::move(*(MySQLResponse *)resp);
		state_ = WFT_STATE_TASK_ERROR;
		error_ = WFT_ERR_MYSQL_HOST_NOT_ALLOWED;
		return 0;
	}

	if (is_ssl_)
	{
		if (resp->get_capability_flags() & 0x800)
		{
			static SSL_CTX *ssl_ctx = WFGlobal::get_ssl_client_ctx();

			ssl = __create_ssl(ssl_ctx_ ? ssl_ctx_ : ssl_ctx);
			if (!ssl)
			{
				state_ = WFT_STATE_SYS_ERROR;
				error_ = errno;
				return 0;
			}

			SSL_set_connect_state(ssl);
		}
		else
		{
			this->resp = std::move(*(MySQLResponse *)resp);
			state_ = WFT_STATE_TASK_ERROR;
			error_ = WFT_ERR_MYSQL_SSL_NOT_SUPPORTED;
			return 0;
		}

	}

	auto *conn = this->get_connection();
	auto *my_conn = new MyConnection(ssl);

	my_conn->str = resp->get_auth_plugin_name();
	if (!password_.empty() && my_conn->str == "sha256_password")
		my_conn->str = "caching_sha2_password";

	resp->get_seed(my_conn->seed);
	my_conn->state = is_ssl_ ? ST_SSL_REQUEST : ST_AUTH_REQUEST;
	my_conn->mysql_seqid = resp->get_seqid() + 1;
	conn->set_context(my_conn, [](void *ctx) {
		auto *my_conn = (MyConnection *)ctx;
		if (my_conn->ssl)
			SSL_free(my_conn->ssl);
		delete my_conn;
	});

	return MYSQL_KEEPALIVE_DEFAULT;
}

int ComplexMySQLTask::auth_switch(MySQLAuthResponse *resp, MyConnection *conn)
{
	std::string name = resp->get_auth_plugin_name();

	if (conn->state != ST_AUTH_REQUEST ||
		(name == "mysql_clear_password" && !is_ssl_))
	{
		state_ = WFT_STATE_SYS_ERROR;
		error_ = EBADMSG;
		return 0;
	}

	if (password_.empty())
	{
		conn->state = ST_CLEAR_PASSWORD_REQUEST;
	}
	else if (name == "sha256_password")
	{
		if (is_ssl_)
			conn->state = ST_CLEAR_PASSWORD_REQUEST;
		else
			conn->state = ST_SHA256_PUBLIC_KEY_REQUEST;
	}
	else
	{
		conn->str = std::move(name);
		conn->state = ST_AUTH_SWITCH_REQUEST;
	}

	resp->get_seed(conn->seed);
	conn->mysql_seqid = resp->get_seqid() + 1;
	return MYSQL_KEEPALIVE_DEFAULT;
}

int ComplexMySQLTask::keep_alive_timeout()
{
	auto *msg = (ProtocolMessage *)this->get_message_in();
	MySQLAuthResponse *auth_resp;
	MySQLResponse *resp;

	state_ = WFT_STATE_SUCCESS;
	error_ = 0;
	if (this->get_seq() == 0)
		return check_handshake((MySQLHandshakeResponse *)msg);

	auto *conn = (MyConnection *)this->get_connection();
	if (conn->state == ST_SSL_REQUEST)
	{
		conn->state = ST_AUTH_REQUEST;
		conn->mysql_seqid++;
		return MYSQL_KEEPALIVE_DEFAULT;
	}

	if (is_ssl_)
		resp = (MySQLResponse *)((MySSLWrapper *)msg)->get_msg();
	else
		resp = (MySQLResponse *)msg;

	switch (conn->state)
	{
	case ST_AUTH_REQUEST:
	case ST_AUTH_SWITCH_REQUEST:
	case ST_CLEAR_PASSWORD_REQUEST:
	case ST_RSA_AUTH_REQUEST:
		if (resp->is_ok_packet())
		{
			if (!res_charset_.empty())
				conn->state = ST_CHARSET_REQUEST;
			else
				conn->state = ST_FIRST_USER_REQUEST;

			break;
		}

		if (resp->is_error_packet() ||
			conn->state == ST_CLEAR_PASSWORD_REQUEST ||
			conn->state == ST_RSA_AUTH_REQUEST)
		{
			this->resp = std::move(*resp);
			state_ = WFT_STATE_TASK_ERROR;
			error_ = WFT_ERR_MYSQL_ACCESS_DENIED;
			return 0;
		}

		auth_resp = (MySQLAuthResponse *)resp;
		if (auth_resp->is_continue())
		{
			if (is_ssl_)
				conn->state = ST_CLEAR_PASSWORD_REQUEST;
			else
				conn->state = ST_CSHA2_PUBLIC_KEY_REQUEST;

			break;
		}

		return auth_switch(auth_resp, conn);

	case ST_SHA256_PUBLIC_KEY_REQUEST:
	case ST_CSHA2_PUBLIC_KEY_REQUEST:
		conn->str = ((MySQLPublicKeyResponse *)resp)->get_public_key();
		conn->state = ST_RSA_AUTH_REQUEST;
		break;

	case ST_CHARSET_REQUEST:
		if (!resp->is_ok_packet())
		{
			this->resp = std::move(*resp);
			state_ = WFT_STATE_TASK_ERROR;
			error_ = WFT_ERR_MYSQL_INVALID_CHARACTER_SET;
			return 0;
		}

		conn->state = ST_FIRST_USER_REQUEST;
		return MYSQL_KEEPALIVE_DEFAULT;

	case ST_FIRST_USER_REQUEST:
		conn->state = ST_USER_REQUEST;
	case ST_USER_REQUEST:
		return this->keep_alive_timeo;

	default:
		assert(0);
		return 0;
	}

	conn->mysql_seqid = resp->get_seqid() + 1;
	return MYSQL_KEEPALIVE_DEFAULT;
}

int ComplexMySQLTask::first_timeout()
{
	return is_user_request_ ? this->watch_timeo : 0;
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
		this->set_fixed_addr(true);
		this->set_fixed_conn(true);
		this->WFComplexClientTask::set_info(info + ("|txn:" + transaction));
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

	if (this->is_fixed_conn())
	{
		if (this->state != WFT_STATE_SUCCESS || this->keep_alive_timeo == 0)
		{
			if (this->target)
				((RouteManager::RouteTarget *)this->target)->state = 0;
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
	if (task->is_fixed_conn())
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
	if (task->is_fixed_conn())
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
					  std::function<void (WFMySQLTask *)>& proc):
		WFServerTask(service, WFGlobal::get_scheduler(), proc)
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


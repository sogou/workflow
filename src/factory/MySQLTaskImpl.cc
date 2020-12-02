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
#include "WFTaskError.h"
#include "WFTaskFactory.h"
#include "MySQLMessage.h"
#include "StringUtil.h"
#include "mysql_types.h"

using namespace protocol;

#define MYSQL_KEEPALIVE_DEFAULT		(180 * 1000)
#define MYSQL_KEEPALIVE_TRANSACTION	(3600 * 1000)

/**********Client**********/

struct handshake_ctx
{
	char challenge[20];
	unsigned char mysql_seqid;
};

class ComplexMySQLTask : public WFComplexClientTask<MySQLRequest, MySQLResponse>
{
protected:
	virtual bool check_request();
	virtual CommMessageOut *message_out();
	virtual CommMessageIn *message_in();
	virtual int keep_alive_timeout();
	virtual bool init_success();
	virtual bool finish_once();

private:
	std::string username_;
	std::string password_;
	std::string db_;
	std::string res_charset_;
	int character_set_;
#define NO_TRANSACTION          -1
#define TRANSACTION_OUT         0
#define TRANSACTION_IN          1
#define TRANSACTION_CONN_RESET  -2
	int transaction_state_;
#define PREPARE_IN              2
	bool succ_;
	bool is_user_request_;

public:
	bool is_transaction() const
	{
		return transaction_state_ == TRANSACTION_IN ||
			   transaction_state_ == TRANSACTION_OUT;
	}

	ComplexMySQLTask(int retry_max, mysql_callback_t&& callback):
		WFComplexClientTask(retry_max, std::move(callback)),
		character_set_(33),
		transaction_state_(NO_TRANSACTION),
		is_user_request_(true)
	{}
};

static inline bool is_trans_begin(const std::string& cmd)
{
	return strncasecmp(cmd.c_str(), "BEGIN", 5) == 0 ||
		   strncasecmp(cmd.c_str(), "START TRANSACTION", 17) == 0;
}

static inline bool is_trans_end(const std::string& cmd)
{
	return strncasecmp(cmd.c_str(), "ROLLBACK", 8) == 0 ||
		   strncasecmp(cmd.c_str(), "COMMIT", 6) == 0;
}

static inline bool is_prepare(const std::string& cmd)
{
	return strncasecmp(cmd.c_str(), "PREPARE", 7) == 0;
}

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

CommMessageOut *ComplexMySQLTask::message_out()
{
	long long seqid = this->get_seq();
	MySQLRequest *req;

	if (seqid == 0)
		req = new MySQLHandshakeRequest;
	else if (seqid == 1)
	{
		auto *auth_req = new MySQLAuthRequest;
		auto *conn = this->get_connection();
		auto *ctx = static_cast<handshake_ctx *>(conn->get_context());

		auth_req->set_seqid(ctx->mysql_seqid);
		auth_req->set_challenge(ctx->challenge);
		delete ctx;
		conn->set_context(NULL, nullptr);
		auth_req->set_auth(username_, password_, db_, character_set_);
		req = auth_req;
	}
	else if (seqid == 2 && res_charset_.size() != 0)
	{
		req = new MySQLRequest;
		req->set_query("SET NAMES " + res_charset_);
	}
	else
		req = NULL;

	if (req)
	{
		succ_ = false;
		is_user_request_ = false;
		return req;
	}

	if (is_transaction())
	{
		auto *target = static_cast<RouteManager::RouteTarget *>(this->get_target());

		if (seqid <= 3 && (seqid == 2 || res_charset_.size() != 0) &&
			(target->state & (TRANSACTION_IN | PREPARE_IN)))
		{
			target->state = TRANSACTION_OUT;
			transaction_state_ = TRANSACTION_CONN_RESET;
			errno = ECONNRESET;
			return NULL;
		}
		else
		{
			bool need_update = false;

			transaction_state_ = (target->state & 1);
			bool in_prepare = ((target->state & 2) != 0);

			if (!in_prepare && is_prepare(this->req.get_query()))
			{
				in_prepare = true;
				need_update = true;
			}

			if (transaction_state_ == TRANSACTION_OUT) // not begin
			{
				if (is_trans_begin(this->req.get_query()))
				{
					transaction_state_ = TRANSACTION_IN;
					need_update = true;
				}
			}
			else if (transaction_state_ == TRANSACTION_IN) // already begin
			{
				if (is_trans_end(this->req.get_query()))
				{
					transaction_state_ = TRANSACTION_OUT;
					need_update = true;
				}
			}

			if (need_update)
			{
				target->state = transaction_state_;
				if (in_prepare)
					target->state |= PREPARE_IN;
			}
		}
	}

	return this->WFClientTask::message_out();
}

CommMessageIn *ComplexMySQLTask::message_in()
{
	long long seqid = this->get_seq();

	if (seqid == 0)
		return new MySQLHandshakeResponse;
	else if (seqid == 1)
		return new MySQLAuthResponse;
	else if (seqid == 2 && !is_user_request_)
		return new MySQLResponse;

	return this->WFClientTask::message_in();
}

int ComplexMySQLTask::keep_alive_timeout()
{
	long long seqid = this->get_seq();

	if (seqid == 0)
	{
		auto *resp = static_cast<MySQLHandshakeResponse *>(this->get_message_in());

		if (resp->host_disallowed())
		{
			this->resp = std::move(*static_cast<MySQLResponse *>(resp));
			succ_ = false;
			return 0;
		}
		else
		{
			auto *ctx = new handshake_ctx();
			auto *conn = this->get_connection();

			ctx->mysql_seqid = resp->get_seqid() + 1;
			resp->get_challenge(ctx->challenge);
			conn->set_context(ctx, [](void *ctx) {
				delete static_cast<handshake_ctx *>(ctx);
			});

			succ_ = true;
		}
	}
	else if (!is_user_request_)
	{
		auto *resp = static_cast<MySQLResponse *>(this->get_message_in());

		succ_ = resp->is_ok_packet();
		if (!succ_)
		{
			this->resp = std::move(*resp);
			return 0;
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
	TransportType type;

	if (uri_.scheme && strcasecmp(uri_.scheme, "mysql") == 0)
		type = TT_TCP;
	//else if (uri_.scheme && strcasecmp(uri_.scheme, "mysql_ssl") == 0)
	//	type = TT_TCP_SSL;
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

	snprintf(info, info_len, "mysql|user:%s|pass:%s|db:%s|"
							 "charset:%d|rcharset:%s",
			 username_.c_str(), password_.c_str(), db_.c_str(),
			 character_set_, res_charset_.c_str());
	this->WFComplexClientTask::set_type(type);

	if (!transaction.empty())
	{
		transaction_state_ = TRANSACTION_OUT;
		this->WFComplexClientTask::set_info(std::string("?maxconn=1&") +
											info + "|txn:" + transaction);
		this->first_addr_only_ = true;
	}
	else
	{
		transaction_state_ = NO_TRANSACTION;
		this->WFComplexClientTask::set_info(info);
		this->first_addr_only_ = false;
	}

	delete []info;
	return true;
}

bool ComplexMySQLTask::finish_once()
{
	if (!is_user_request_)
	{
		is_user_request_ = true;
		delete this->get_message_out();
		delete this->get_message_in();

		if (this->state == WFT_STATE_SUCCESS && !succ_)
		{
			long long seqid = this->get_seq();

			if (seqid == 0)
				this->error = WFT_ERR_MYSQL_HOST_NOT_ALLOWED;
			else if (seqid == 1)
				this->error = WFT_ERR_MYSQL_ACCESS_DENIED;
			else
				this->error = WFT_ERR_MYSQL_INVALID_CHARACTER_SET;

			this->disable_retry();
			this->state = WFT_STATE_TASK_ERROR;
		}

		return false;
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
	if (task->is_transaction())
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
	if (task->is_transaction())
		task->set_keep_alive(MYSQL_KEEPALIVE_TRANSACTION);
	else
		task->set_keep_alive(MYSQL_KEEPALIVE_DEFAULT);

	return task;
}

/**********Server**********/

class WFMySQLServerTask : public WFServerTask<MySQLRequest, MySQLResponse>
{
public:
	WFMySQLServerTask(std::function<void (WFMySQLTask *)>& process):
		WFServerTask(WFGlobal::get_scheduler(), process)
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

WFMySQLTask *WFServerTaskFactory::create_mysql_task(std::function<void (WFMySQLTask *)>& process)
{
	return new WFMySQLServerTask(process);
}


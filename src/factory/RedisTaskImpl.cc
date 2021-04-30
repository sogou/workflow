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
           Li Yingxin (liyingxin@sogou-inc.com)
           Liu Kai (liukaidx@sogou-inc.com)
*/

#include <stdio.h>
#include <string>
#include "WFTaskError.h"
#include "WFTaskFactory.h"
#include "StringUtil.h"

using namespace protocol;

#define REDIS_KEEPALIVE_DEFAULT		(180 * 1000)
#define REDIS_REDIRECT_MAX			3

/**********Client**********/

class ComplexRedisTask : public WFComplexClientTask<RedisRequest, RedisResponse>
{
public:
	ComplexRedisTask(int retry_max, redis_callback_t&& callback):
		WFComplexClientTask(retry_max, std::move(callback)),
		db_num_(0),
		is_user_request_(true),
		redirect_count_(0)
	{}

protected:
	virtual bool check_request();
	virtual CommMessageOut *message_out();
	virtual CommMessageIn *message_in();
	virtual int keep_alive_timeout();
	virtual bool init_success();
	virtual bool finish_once();

private:
	bool need_redirect();

	std::string password_;
	int db_num_;
	bool succ_;
	bool is_user_request_;
	int redirect_count_;
};

bool ComplexRedisTask::check_request()
{
	std::string command;

	if (this->req.get_command(command) &&
		(strcasecmp(command.c_str(), "AUTH") == 0 ||
		 strcasecmp(command.c_str(), "SELECT") == 0 ||
		 strcasecmp(command.c_str(), "ASKING") == 0))
	{
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_REDIS_COMMAND_DISALLOWED;
		return false;
	}

	return true;
}

CommMessageOut *ComplexRedisTask::message_out()
{
	long long seqid = this->get_seq();

	if (seqid <= 1)
	{
		if (seqid == 0 && !password_.empty())
		{
			succ_ = false;
			is_user_request_ = false;
			auto *auth_req = new RedisRequest;

			auth_req->set_request("AUTH", {password_});
			return auth_req;
		}

		if (db_num_ > 0)
		{
			succ_ = false;
			is_user_request_ = false;
			auto *select_req = new RedisRequest;
			char buf[32];

			sprintf(buf, "%d", db_num_);
			select_req->set_request("SELECT", {buf});
			return select_req;
		}
	}

	return this->WFClientTask::message_out();
}

CommMessageIn *ComplexRedisTask::message_in()
{
	RedisRequest *req = this->get_req();
	RedisResponse *resp = this->get_resp();

	if (is_user_request_)
		resp->set_asking(req->is_asking());
	else
		resp->set_asking(false);

	return this->WFClientTask::message_in();
}

int ComplexRedisTask::keep_alive_timeout()
{
	if (this->is_user_request_)
		return this->keep_alive_timeo;

	RedisResponse *resp = this->get_resp();

	succ_ = (resp->parse_success() &&
			 resp->result_ptr()->type != REDIS_REPLY_TYPE_ERROR);

	return succ_ ? REDIS_KEEPALIVE_DEFAULT : 0;
}

bool ComplexRedisTask::init_success()
{
	TransportType type;

	if (uri_.scheme && strcasecmp(uri_.scheme, "redis") == 0)
		type = TT_TCP;
	else if (uri_.scheme && strcasecmp(uri_.scheme, "rediss") == 0)
		type = TT_TCP_SSL;
	else
	{
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_URI_SCHEME_INVALID;
		return false;
	}

	//todo redis+unix
	//https://stackoverflow.com/questions/26964595/whats-the-correct-way-to-use-a-unix-domain-socket-in-requests-framework
	//https://stackoverflow.com/questions/27037990/connecting-to-postgres-via-database-url-and-unix-socket-in-rails

	//todo userinfo=username:password
	if (uri_.userinfo && uri_.userinfo[0] == ':' && uri_.userinfo[1])
	{
		password_.assign(uri_.userinfo + 1);
		StringUtil::url_decode(password_);
	}

	if (uri_.path && uri_.path[0] == '/' && uri_.path[1])
		db_num_ = atoi(uri_.path + 1);

	size_t info_len = password_.size() + 32 + 16;
	char *info = new char[info_len];

	sprintf(info, "redis|pass:%s|db:%d", password_.c_str(), db_num_);
	this->WFComplexClientTask::set_transport_type(type);
	this->WFComplexClientTask::set_info(info);

	delete []info;
	return true;
}

bool ComplexRedisTask::need_redirect()
{
	RedisRequest *client_req = this->get_req();
	RedisResponse *client_resp = this->get_resp();
	redis_reply_t *reply = client_resp->result_ptr();

	if (reply->type == REDIS_REPLY_TYPE_ERROR)
	{
		if (reply->str == NULL)
			return false;

		bool asking = false;
		if (strncasecmp(reply->str, "ASK ", 4) == 0)
			asking = true;
		else if (strncasecmp(reply->str, "MOVED ", 6) != 0)
			return false;

		if (redirect_count_ >= REDIS_REDIRECT_MAX)
			return false;

		std::string err_str(reply->str, reply->len);
		auto split_result = StringUtil::split_filter_empty(err_str, ' ');
		if (split_result.size() == 3)
		{
			client_req->set_asking(asking);

			// format: COMMAND SLOT HOSTPORT
			// example: MOVED/ASK 123 127.0.0.1:6379
			std::string& hostport = split_result[2];
			redirect_count_++;

			ParsedURI uri;
			std::string url;
			url.append(uri_.scheme);
			url.append("://");
			url.append(hostport);

			URIParser::parse(url, uri);
			std::swap(uri.host, uri_.host);
			std::swap(uri.port, uri_.port);
			std::swap(uri.state, uri_.state);
			std::swap(uri.error, uri_.error);

			return true;
		}
		return false;
	}

	return false;
}

bool ComplexRedisTask::finish_once()
{
	if (!is_user_request_)
	{
		is_user_request_ = true;
		delete this->get_message_out();

		if (this->state == WFT_STATE_SUCCESS)
		{
			if (succ_)
				this->clear_resp();
			else
			{
				this->disable_retry();
				this->state = WFT_STATE_TASK_ERROR;
				this->error = WFT_ERR_REDIS_ACCESS_DENIED;
			}
		}
		return false;
	}

	if (this->state == WFT_STATE_SUCCESS)
	{
		if (need_redirect())
			this->set_redirect(uri_);
		else if (this->state != WFT_STATE_SUCCESS)
			this->disable_retry();
	}

	return true;
}

/**********Factory**********/

// redis://:password@host:port/db_num
// url = "redis://:admin@192.168.1.101:6001/3"
// url = "redis://127.0.0.1:6379"
WFRedisTask *WFTaskFactory::create_redis_task(const std::string& url,
											  int retry_max,
											  redis_callback_t callback)
{
	auto *task = new ComplexRedisTask(retry_max, std::move(callback));
	ParsedURI uri;

	URIParser::parse(url, uri);
	task->init(std::move(uri));
	task->set_keep_alive(REDIS_KEEPALIVE_DEFAULT);
	return task;
}

WFRedisTask *WFTaskFactory::create_redis_task(const ParsedURI& uri,
											  int retry_max,
											  redis_callback_t callback)
{
	auto *task = new ComplexRedisTask(retry_max, std::move(callback));

	task->init(uri);
	task->set_keep_alive(REDIS_KEEPALIVE_DEFAULT);
	return task;
}


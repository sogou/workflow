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
           Xie Han (xiehan@sogou-inc.com)
*/

#include <stdio.h>
#include <string.h>
#include <string>
#include "PackageWrapper.h"
#include "WFTaskError.h"
#include "WFTaskFactory.h"
#include "StringUtil.h"
#include "RedisTaskImpl.inl"

using namespace protocol;

#define REDIS_KEEPALIVE_DEFAULT		(60 * 1000)
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
	virtual int first_timeout();
	virtual bool init_success();
	virtual bool finish_once();

protected:
	bool need_redirect();

	std::string username_;
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
		if (seqid == 0 && (!password_.empty() || !username_.empty()))
		{
			auto *auth_req = new RedisRequest;

			if (!username_.empty())
				auth_req->set_request("AUTH", {username_, password_});
			else
				auth_req->set_request("AUTH", {password_});

			succ_ = false;
			is_user_request_ = false;
			return auth_req;
		}

		if (db_num_ > 0 &&
			(seqid == 0 || !password_.empty() || !username_.empty()))
		{
			auto *select_req = new RedisRequest;
			char buf[32];

			sprintf(buf, "%d", db_num_);
			select_req->set_request("SELECT", {buf});

			succ_ = false;
			is_user_request_ = false;
			return select_req;
		}
	}

	return this->WFComplexClientTask::message_out();
}

CommMessageIn *ComplexRedisTask::message_in()
{
	RedisRequest *req = this->get_req();
	RedisResponse *resp = this->get_resp();

	if (is_user_request_)
		resp->set_asking(req->is_asking());
	else
		resp->set_asking(false);

	return this->WFComplexClientTask::message_in();
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

int ComplexRedisTask::first_timeout()
{
	return is_user_request_ ? this->watch_timeo : 0;
}

bool ComplexRedisTask::init_success()
{
	enum TransportType type;

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

	if (uri_.userinfo)
	{
		char *p = strchr(uri_.userinfo, ':');
		if (p)
		{
			username_.assign(uri_.userinfo, p);
			password_.assign(p + 1);
			StringUtil::url_decode(username_);
			StringUtil::url_decode(password_);
		}
		else
		{
			username_.assign(uri_.userinfo);
			StringUtil::url_decode(username_);
		}
	}

	if (uri_.path && uri_.path[0] == '/' && uri_.path[1])
		db_num_ = atoi(uri_.path + 1);

	size_t info_len = username_.size() + password_.size() + 32 + 32;
	char *info = new char[info_len];

	sprintf(info, "redis|user:%s|pass:%s|db:%d", username_.c_str(),
			password_.c_str(), db_num_);
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

		if (strncasecmp(reply->str, "NOAUTH ", 7) == 0)
		{
			this->state = WFT_STATE_TASK_ERROR;
			this->error = WFT_ERR_REDIS_ACCESS_DENIED;
			return false;
		}

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

/****** Redis Subscribe ******/

class ComplexRedisSubscribeTask : public ComplexRedisTask
{
public:
	virtual int push(const void *buf, size_t size)
	{
		if (finished_)
		{
			errno = ENOENT;
			return -1;
		}

		if (!watching_)
		{
			errno = EAGAIN;
			return -1;
		}

		return this->scheduler->push(buf, size, this);
	}

protected:
	virtual CommMessageIn *message_in()
	{
		if (!is_user_request_)
			return this->ComplexRedisTask::message_in();

		return &wrapper_;
	}

	virtual int first_timeout()
	{
		return watching_ ? this->watch_timeo : 0;
	}

protected:
	class SubscribeWrapper : public PackageWrapper
	{
	protected:
		virtual ProtocolMessage *next_in(ProtocolMessage *message);

	protected:
		ComplexRedisSubscribeTask *task_;

	public:
		SubscribeWrapper(ComplexRedisSubscribeTask *task) :
			PackageWrapper(task->get_resp())
		{
			task_ = task;
		}
	};

protected:
	SubscribeWrapper wrapper_;
	bool watching_;
	bool finished_;
	std::function<void (WFRedisTask *)> extract_;

public:
	ComplexRedisSubscribeTask(std::function<void (WFRedisTask *)>&& extract,
							  redis_callback_t&& callback) :
		ComplexRedisTask(0, std::move(callback)),
		wrapper_(this),
		extract_(std::move(extract))
	{
		watching_ = false;
		finished_ = false;
	}
};

ProtocolMessage *
ComplexRedisSubscribeTask::SubscribeWrapper::next_in(ProtocolMessage *message)
{
	redis_reply_t *reply = ((RedisResponse *)message)->result_ptr();

	if (reply->type == REDIS_REPLY_TYPE_ARRAY && reply->elements == 3 &&
		reply->element[0]->type == REDIS_REPLY_TYPE_STRING)
	{
		const char *str = reply->element[0]->str;
		size_t len = reply->element[0]->len;

		if ((len == 11 && strncasecmp(str, "unsubscribe", 11)) == 0 ||
			(len == 12 && strncasecmp(str, "punsubscribe", 12) == 0))
		{
			if (reply->element[2]->type == REDIS_REPLY_TYPE_INTEGER &&
				reply->element[2]->integer == 0)
			{
				task_->finished_ = true;
			}
		}
	}
	else if (!task_->watching_)
	{
		task_->finished_ = true;
		return NULL;
	}

	task_->watching_ = true;
	task_->extract_(task_);

	task_->clear_resp();
	return task_->finished_ ? NULL : &task_->resp;
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

WFRedisTask *
__WFRedisTaskFactory::create_subscribe_task(const std::string& url,
											extract_t extract,
											redis_callback_t callback)
{
	auto *task = new ComplexRedisSubscribeTask(std::move(extract),
											   std::move(callback));
	ParsedURI uri;

	URIParser::parse(url, uri);
	task->init(std::move(uri));
	return task;
}

WFRedisTask *
__WFRedisTaskFactory::create_subscribe_task(const ParsedURI& uri,
											extract_t extract,
											redis_callback_t callback)
{
	auto *task = new ComplexRedisSubscribeTask(std::move(extract),
											   std::move(callback));

	task->init(uri);
	return task;
}


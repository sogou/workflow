/*
  Copyright (c) 2024 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Xie Han (xiehan@sogou-inc.com)
*/

#include <errno.h>
#include <string>
#include <vector>
#include <mutex>
#include "URIParser.h"
#include "RedisTaskImpl.inl"
#include "WFRedisSubscriber.h"

int WFRedisSubscribeTask::sync_send(const std::string& command,
									const std::vector<std::string>& params)
{
	std::string str("*" + std::to_string(1 + params.size()) + "\r\n");
	int ret;

	str += "$" + std::to_string(command.size()) + "\r\n" + command + "\r\n";
	for (const std::string& p : params)
		str += "$" + std::to_string(p.size()) + "\r\n" + p + "\r\n";

	this->mutex.lock();
	if (this->task)
	{
		ret = this->task->push(str.c_str(), str.size());
		if (ret == (int)str.size())
			ret = 0;
		else
		{
			if (ret >= 0)
				errno = ENOBUFS;
			ret = -1;
		}
	}
	else
	{
		errno = ENOENT;
		ret = -1;
	}

	this->mutex.unlock();
	return ret;
}

void WFRedisSubscribeTask::task_extract(WFRedisTask *task)
{
	auto *t = (WFRedisSubscribeTask *)task->user_data;

	if (t->extract)
		t->extract(t);
}

void WFRedisSubscribeTask::task_callback(WFRedisTask *task)
{
	auto *t = (WFRedisSubscribeTask *)task->user_data;

	t->mutex.lock();
	t->task = NULL;
	t->mutex.unlock();

	t->state = task->get_state();
	t->error = task->get_error();
	if (t->callback)
		t->callback(t);

	t->release();
}

int WFRedisSubscriber::init(const std::string& url, SSL_CTX *ssl_ctx)
{
	if (URIParser::parse(url, this->uri) >= 0)
	{
		this->ssl_ctx = ssl_ctx;
		return 0;
	}

	if (this->uri.state == URI_STATE_INVALID)
		errno = EINVAL;

	return -1;
}

WFRedisTask *
WFRedisSubscriber::create_redis_task(const std::string& command,
									 const std::vector<std::string>& params)
{
	WFRedisTask *task = __WFRedisTaskFactory::create_subscribe_task(this->uri,
									WFRedisSubscribeTask::task_extract,
									WFRedisSubscribeTask::task_callback);
	this->set_ssl_ctx(task);
	task->get_req()->set_request(command, params);
	return task;
}

WFRedisSubscribeTask *
WFRedisSubscriber::create_subscribe_task(
						const std::vector<std::string>& channels,
						extract_t extract, callback_t callback)
{
	WFRedisTask *task = this->create_redis_task("SUBSCRIBE", channels);
	return new WFRedisSubscribeTask(task, std::move(extract),
									std::move(callback));
}

WFRedisSubscribeTask *
WFRedisSubscriber::create_psubscribe_task(
						const std::vector<std::string>& patterns,
						extract_t extract, callback_t callback)
{
	WFRedisTask *task = this->create_redis_task("PSUBSCRIBE", patterns);
	return new WFRedisSubscribeTask(task, std::move(extract),
									std::move(callback));
}


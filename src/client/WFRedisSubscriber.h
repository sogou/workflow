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

#ifndef _WFREDISSUBSCRIBER_H_
#define _WFREDISSUBSCRIBER_H_

#include <errno.h>
#include <string>
#include <vector>
#include <utility>
#include <functional>
#include <atomic>
#include <mutex>
#include <openssl/ssl.h>
#include "WFTask.h"
#include "WFTaskFactory.h"

class WFRedisSubscribeTask : public WFGenericTask
{
public:
	/* Note: Call 'get_resp()' only in the 'extract' function or
	   before the task is started to set response size limit. */
	protocol::RedisResponse *get_resp()
	{
		return this->task->get_resp();
	}

public:
	/* User needs to call 'release()' exactly once, anywhere. */
	void release()
	{
		if (this->flag.exchange(true))
			delete this;
	}

public:
	/* Note: After 'release()' is called, all the requesting functions
	   should not be called except in 'extract', because the task
	   point may have been deleted because 'callback' finished. */

	int subscribe(const std::vector<std::string>& channels)
	{
		return this->sync_send("SUBSCRIBE", channels);
	}

	int unsubscribe(const std::vector<std::string>& channels)
	{
		return this->sync_send("UNSUBSCRIBE", channels);
	}

	int unsubscribe()
	{
		return this->sync_send("UNSUBSCRIBE", { });
	}

	int psubscribe(const std::vector<std::string>& patterns)
	{
		return this->sync_send("PSUBSCRIBE", patterns);
	}

	int punsubscribe(const std::vector<std::string>& patterns)
	{
		return this->sync_send("PUNSUBSCRIBE", patterns);
	}

	int punsubscribe()
	{
		return this->sync_send("PUNSUBSCRIBE", { });
	}

	int ping(const std::string& message)
	{
		return this->sync_send("PING", { message });
	}

	int ping()
	{
		return this->sync_send("PING", { });
	}

	int quit()
	{
		return this->sync_send("QUIT", { });
	}

public:
	/* All 'timeout' proxy functions can only be called only before
	   the task is started or in 'extract'. */

	/* Timeout of waiting for each message. Very useful. If not set,
	   the max waiting time will be the global 'response_timeout'*/
	void set_watch_timeout(int timeout)
	{
		this->task->set_watch_timeout(timeout);
	}

	/* Timeout of receiving a complete message. */
	void set_recv_timeout(int timeout)
	{
		this->task->set_receive_timeout(timeout);
	}

	/* Timeout of sending the first subscribe request. */
	void set_send_timeout(int timeout)
	{
		this->task->set_send_timeout(timeout);
	}

	/* The default keep alive timeout is 0. If you want to keep
	   the connection alive, make sure not to send any request
	   after all channels/patterns were unsubscribed. */
	void set_keep_alive(int timeout)
	{
		this->task->set_keep_alive(timeout);
	}

public:
	/* Call 'set_extract' or 'set_callback' only before the task
	   is started, or in 'extract'. */

	void set_extract(std::function<void (WFRedisSubscribeTask *)> ex)
	{
		this->extract = std::move(ex);
	}

	void set_callback(std::function<void (WFRedisSubscribeTask *)> cb)
	{
		this->callback = std::move(cb);
	}

protected:
	virtual void dispatch()
	{
		series_of(this)->push_front(this->task);
		this->subtask_done();
	}

	virtual SubTask *done()
	{
		return series_of(this)->pop();
	}

protected:
	int sync_send(const std::string& command,
				  const std::vector<std::string>& params);
	static void task_extract(WFRedisTask *task);
	static void task_callback(WFRedisTask *task);

protected:
	WFRedisTask *task;
	std::mutex mutex;
	std::atomic<bool> flag;
	std::function<void (WFRedisSubscribeTask *)> extract;
	std::function<void (WFRedisSubscribeTask *)> callback;

protected:
	WFRedisSubscribeTask(WFRedisTask *task,
						 std::function<void (WFRedisSubscribeTask *)>&& ex,
						 std::function<void (WFRedisSubscribeTask *)>&& cb) :
		flag(false),
		extract(std::move(ex)),
		callback(std::move(cb))
	{
		task->user_data = this;
		this->task = task;
	}

	virtual ~WFRedisSubscribeTask()
	{
		if (this->task)
			this->task->dismiss();
	}

	friend class WFRedisSubscriber;
};

class WFRedisSubscriber
{
public:
	int init(const std::string& url)
	{
		return this->init(url, NULL);
	}

	int init(const std::string& url, SSL_CTX *ssl_ctx);

	void deinit() { }

public:
	using extract_t = std::function<void (WFRedisSubscribeTask *)>;
	using callback_t = std::function<void (WFRedisSubscribeTask *)>;

public:
	WFRedisSubscribeTask *
	create_subscribe_task(const std::vector<std::string>& channels,
						  extract_t extract, callback_t callback);

	WFRedisSubscribeTask *
	create_psubscribe_task(const std::vector<std::string>& patterns,
						   extract_t extract, callback_t callback);

protected:
	void set_ssl_ctx(WFRedisTask *task) const
	{
		using RedisRequest = protocol::RedisRequest;
		using RedisResponse = protocol::RedisResponse;
		auto *t = (WFComplexClientTask<RedisRequest, RedisResponse> *)task;
		/* 'ssl_ctx' can be NULL and will use default. */
		t->set_ssl_ctx(this->ssl_ctx);
	}

protected:
	WFRedisTask *create_redis_task(const std::string& command,
								   const std::vector<std::string>& params);

protected:
	ParsedURI uri;
	SSL_CTX *ssl_ctx;

public:
	virtual ~WFRedisSubscriber() { }
};

#endif


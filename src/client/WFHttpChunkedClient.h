/*
  Copyright (c) 2025 Sogou, Inc.

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

#ifndef _WFHTTPCHUNKEDCLIENT_H_
#define _WFHTTPCHUNKEDCLIENT_H_

#include <utility>
#include <functional>
#include <openssl/ssl.h>
#include "HttpMessage.h"
#include "WFTask.h"
#include "WFTaskFactory.h"
#include "HttpTaskImpl.inl"

class WFHttpChunkedTask : public WFGenericTask
{
public:
	protocol::HttpMessageChunk *get_chunk() const
	{
		return this->chunk;
	}

public:
	protocol::HttpRequest *get_req()
	{
		return this->task->get_req();
	}

	protocol::HttpResponse *get_resp()
	{
		return this->task->get_resp();
	}

	const protocol::HttpRequest *get_req() const
	{
		return this->task->get_req();
	}

	const protocol::HttpResponse *get_resp() const
	{
		return this->task->get_resp();
	}

public:
	void set_watch_timeout(int timeout)
	{
		this->task->set_watch_timeout(timeout);
	}

	void set_recv_timeout(int timeout)
	{
		this->task->set_receive_timeout(timeout);
	}

	void set_send_timeout(int timeout)
    {
        this->task->set_send_timeout(timeout);
    }

	void set_keep_alive(int timeout)
	{
		this->task->set_keep_alive(timeout);
	}

public:
	void set_ssl_ctx(SSL_CTX *ctx)
	{
		using HttpRequest = protocol::HttpRequest;
		using HttpResponse = protocol::HttpResponse;
		auto *t = (WFComplexClientTask<HttpRequest, HttpResponse> *)this->task;
		t->set_ssl_ctx(ctx);
	}

public:
	void set_chunked(std::function<void (const WFHttpChunkedTask *)> ch)
	{
		this->chunked = std::move(ch);
	}

	void set_callback(std::function<void (WFHttpChunkedTask *)> cb)
	{
		this->callback = std::move(cb);
	}

public:
	const WFHttpTask *get_http_task() const
	{
		return this->task;
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
	static void task_chunked(protocol::HttpMessageChunk *chunk,
							 WFHttpTask *task)
	{
		auto *t = (WFHttpChunkedTask *)task->user_data;

		t->chunk = chunk;
		if (t->chunked)
			t->chunked(t);
	}

	static void task_callback(WFHttpTask *task)
	{
		auto *t = (WFHttpChunkedTask *)task->user_data;

		t->state = task->get_state();
		t->error = task->get_error();
		t->chunk = NULL;
		if (t->callback)
			t->callback(t);

		t->task = NULL;
		delete t;
	}

protected:
	WFHttpTask *task;
	protocol::HttpMessageChunk *chunk;
	std::function<void (const WFHttpChunkedTask *)> chunked;
	std::function<void (WFHttpChunkedTask *)> callback;

protected:
	WFHttpChunkedTask(WFHttpTask *task,
					  std::function<void (const WFHttpChunkedTask *)>&& ch,
					  std::function<void (WFHttpChunkedTask *)>&& cb) :
		chunked(std::move(ch)),
		callback(std::move(cb))
	{
		task->user_data = this;
		this->task = task;
	}

	virtual ~WFHttpChunkedTask()
	{
		if (this->task)
			this->task->dismiss();
	}

	friend class WFHttpChunkedClient;
};

class WFHttpChunkedClient
{
public:
	using chunked_t = std::function<void (const WFHttpChunkedTask *)>;
	using callback_t = std::function<void (WFHttpChunkedTask *)>;

public:
	static WFHttpChunkedTask *create_chunked_task(const std::string& url,
												  int redirect_max,
												  chunked_t chunked,
												  callback_t callback)
	{
		WFHttpTask *task = __WFHttpTaskFactory::create_chunked_task(url,
											redirect_max,
											WFHttpChunkedTask::task_chunked,
											WFHttpChunkedTask::task_callback);
		return new WFHttpChunkedTask(task, std::move(chunked),
									 std::move(callback));
	}

	static WFHttpChunkedTask *create_chunked_task(const ParsedURI& uri,
												  int redirect_max,
												  chunked_t chunked,
												  callback_t callback)
	{
		WFHttpTask *task = __WFHttpTaskFactory::create_chunked_task(uri,
											redirect_max,
											WFHttpChunkedTask::task_chunked,
											WFHttpChunkedTask::task_callback);
		return new WFHttpChunkedTask(task, std::move(chunked),
									 std::move(callback));
	}
};

#endif


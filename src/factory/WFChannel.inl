/*
  Copyright (c) 2021 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Li Yingxin (liyingxin@sogou-inc.com)
          Xie Han (xiehan@sogou-inc.com)
*/

#include <random>
#include <functional>
#include "TransRequest.h"
#include "WFTask.h"
#include "WFTaskFactory.h"
#include "WFCondition.h"
#include "WFCondTaskFactory.h"
#include "WFNameService.h"
#include "RouteManager.h"
#include "WFGlobal.h"
#include "EndpointParams.h"
#include "HttpUtil.h"
#include "HttpMessage.h"
#include "WFChannel.h"

template<class MSG>
class WFChannelOutTask : public WFChannelTask<MSG>
{
protected:
	virtual MSG *message_out() { return &this->msg; }

public:
	WFChannelOutTask(CommChannel *channel, CommScheduler *scheduler,
					 std::function<void (WFChannelTask<MSG> *)>&& cb) :
		WFChannelTask<MSG>(channel, scheduler, std::move(cb))
	{
	}

protected:
	virtual ~WFChannelOutTask() { }
};

template<class MSG>
class WFChannelInTask : public WFChannelTask<MSG>
{
protected:
	virtual void dispatch()
	{
		this->state = WFT_STATE_SUCCESS;
		this->error = 0;
		this->process(this);
		this->subtask_done();
	}

public:
	WFChannelInTask(CommChannel *channel, CommScheduler *scheduler,
					std::function<void (WFChannelTask<MSG> *)>& proc) :
		WFChannelTask<MSG>(channel, scheduler, nullptr),
		process(proc)
	{
	}

protected:
	std::function<void (WFChannelTask<MSG> *)>& process;

protected:
	virtual ~WFChannelInTask() { }
};

template<class MSG>
class WFChannel : public ChanRequest
{
public:
	int get_state() const { return this->state; }
	int get_error() const { return this->error; }
	bool is_established() const { return this->established; }

	void set_callback(std::function<void (WFChannel<MSG> *)>&& cb)
	{
		this->callback = std::move(cb);
	}

protected:
	virtual CommMessageIn *message_in()
	{
		this->session = this->new_session();
		return this->session->get_msg();
	}

	virtual WFChannelTask<MSG> *new_session()
	{
		auto *task = new WFChannelInTask<MSG>(this, this->scheduler,
											  this->process);
		Workflow::create_series_work(task, nullptr);
		return task;
	}

	virtual void handle_in(CommMessageIn *in)
	{
		if (this->session)
			this->session->dispatch();
		this->session = NULL;
	}

	virtual SubTask *done()
	{
		if (this->callback)
			this->callback(this);

		return series_of(this)->pop();
	}

protected:
	std::function<void (WFChannelTask<MSG> *)> process;
	std::function<void (WFChannel<MSG> *)> callback;

private:
	WFChannelTask<MSG> *session;

public:
	WFChannel(CommSchedObject *object, CommScheduler *scheduler,
			  std::function<void (WFChannelTask<MSG> *)>&& process) :
		ChanRequest(object, scheduler),
		process(std::move(process))
	{
		this->session = NULL;
	}

protected:
	virtual ~WFChannel() { }
};

/**********WFComplexChannel for sequentially establish and send**********/

template<class MSG>
class WFComplexChannel : public WFChannel<MSG>
{
public:
	void set_uri(const ParsedURI& uri) { this->uri = uri; }
	const ParsedURI *get_uri() const { return &this->uri; }

	int get_error() const { return this->error; }

	void set_state(int state) { this->state = state; }
	int get_state() const { return this->state; }

	void set_sending(bool sending) { this->sending = sending; }
	bool get_sending() const { return this->sending; }

	void set_transport_type(TransportType type) { this->type = type; }
	TransportType get_transport_type() const { return this->type; }

protected:
	virtual void dispatch();
	virtual SubTask *done();
	virtual void handle_terminated();
	virtual WFRouterTask *route();
	void router_callback(WFRouterTask *task);
	void wait_callback(WFMailboxTask *task);

public:
	pthread_mutex_t mutex;
	WFCondition condition;

protected:
	bool sending;
	WFRouterTask *router_task;
	TransportType type;
	ParsedURI uri;
	WFNSPolicy *ns_policy;
	RouteManager::RouteResult route_result;

public:
	WFComplexChannel(CommSchedObject *object, CommScheduler *scheduler,
					 std::function<void (WFChannelTask<MSG> *)>&& process) :
		WFChannel<MSG>(object, scheduler, std::move(process)),
		mutex(PTHREAD_MUTEX_INITIALIZER)
	{
		this->state = WFT_STATE_UNDEFINED;
		this->error = 0;
		this->sending = false;
		this->type = TT_TCP;
	}

protected:
	virtual ~WFComplexChannel() { }
};

template<class MSG>
void WFComplexChannel<MSG>::dispatch()
{
	if (this->object)
		return this->WFChannel<MSG>::dispatch();

	if (this->state == WFT_STATE_UNDEFINED)
	{
		this->router_task = this->route();
		series_of(this)->push_front(this);
		series_of(this)->push_front(this->router_task);
	}

	this->subtask_done();
}

template<class MSG>
SubTask *WFComplexChannel<MSG>::done()
{
	SeriesWork *series = series_of(this);

	if (this->established == 1)
	{
		if (this->state == WFT_STATE_SYS_ERROR)
			this->ns_policy->failed(&this->route_result, NULL, this->target);
		else
			this->ns_policy->success(&this->route_result, NULL, this->target);
	}

	if (this->router_task)
	{
		this->router_task = NULL;
		return series->pop();
	}

	// dispacth() by handle_terminate() or deinit()
	if (this->established == 0 &&
		(WFComplexChannel<MSG> *)series->get_context() == this)
	{
		pthread_mutex_lock(&this->mutex);
		this->sending = false;
		this->condition.signal(NULL);
		pthread_mutex_unlock(&this->mutex);
	}

	if (this->callback)
		this->callback(this);

	if (this->state == WFT_STATE_SUCCESS)
		this->state = WFT_STATE_UNDEFINED;

	return series->pop();
}

template<class MSG>
void WFComplexChannel<MSG>::handle_terminated()
{
	SeriesWork *series;
	SubTask *first;

	if (this->established == 0)
		return;

	pthread_mutex_lock(&this->mutex);
	if (this->sending == false)
	{
		this->sending = true;
		this->set_pointer(NULL);
		first = this;
	}
	else
	{
		first = WFCondTaskFactory::create_wait_task(&this->condition,
					std::bind(&WFComplexChannel<MSG>::wait_callback,
							  this, std::placeholders::_1));
	}
	pthread_mutex_unlock(&this->mutex);

	series = Workflow::create_series_work(first, nullptr);
	series->set_context(this);
	series->start();
}

template<class MSG>
void WFComplexChannel<MSG>::wait_callback(WFMailboxTask *task)
{
	SubTask *next;

	if (this->established == 0)
		return;

	pthread_mutex_lock(&this->mutex);
	if (this->sending == false)
	{
		this->sending = true;
		this->set_pointer(NULL);
		next = this;
	}
	else
	{
		next = WFCondTaskFactory::create_wait_task(&this->condition,
							std::bind(&WFComplexChannel<MSG>::wait_callback,
									  this, std::placeholders::_1));
	}
	pthread_mutex_unlock(&this->mutex);

	series_of(task)->push_back(next);
}

template<class MSG>
WFRouterTask *WFComplexChannel<MSG>::route()
{
	auto&& cb = std::bind(&WFComplexChannel<MSG>::router_callback,
						  this, std::placeholders::_1);
	struct WFNSParams params = {
		.type			=	this->type,
		.uri			=	this->uri,
		.info			=	"",
		.fixed_addr		=	true,
		.retry_times	=	0,
		.tracing		=	NULL,
	};

	WFNameService *ns = WFGlobal::get_name_service();
	this->ns_policy = ns->get_policy(this->uri.host ? this->uri.host : "");
	return this->ns_policy->create_router_task(&params, cb);
}

template<class MSG>
void WFComplexChannel<MSG>::router_callback(WFRouterTask *task)
{
	if (task->get_state() == WFT_STATE_SUCCESS)
	{
		this->route_result = std::move(*task->get_result());
		this->set_request_object(this->route_result.request_object);
	}
	else
	{
		this->state = task->get_state();
		this->error = task->get_error();
	}
}

/**********ComplexChannelOutTask for complex channel and upgrade()**********/

template<class MSG>
class ComplexChannelOutTask : public WFChannelOutTask<MSG>
{
protected:
	virtual void dispatch();
	virtual SubTask *done();
	virtual SubTask *upgrade();
	void upgrade_callback(WFCounterTask *task);

protected:
	bool ready;

public:
	ComplexChannelOutTask(WFComplexChannel<MSG> *channel, CommScheduler *scheduler,
						  std::function<void (WFChannelTask<MSG> *)>&& cb) :
		WFChannelOutTask<MSG>(channel, scheduler, std::move(cb))
	{
		this->state = WFT_STATE_UNDEFINED;
		this->error = 0;
		this->user_data = NULL;
		this->ready = true;
	}

	void switch_callback(void *t);

protected:
	virtual ~ComplexChannelOutTask() { }
};

template<class MSG>
void ComplexChannelOutTask<MSG>::dispatch()
{
	WFMailboxTask *waiter;
	bool should_send = false;
	auto *channel = (WFComplexChannel<MSG> *)this->get_request_channel();

	if (this->state == WFT_STATE_SYS_ERROR ||
		channel->get_state() == WFT_STATE_SYS_ERROR)
	{
		return this->subtask_done();
	}

	pthread_mutex_lock(&channel->mutex);

	switch (channel->get_state())
	{
	case WFT_STATE_UNDEFINED:
		if (channel->get_sending() == false)
		{
			series_of(this)->push_front(this);
			series_of(this)->push_front(channel);
			channel->set_sending(true);
			this->ready = false;
		}
		else if (this->ready == false)
		{
			SubTask *upgrade_task = this->upgrade();
			series_of(this)->push_front(this);
			series_of(this)->push_front(upgrade_task);
		}
		else
		{
			waiter = WFCondTaskFactory::create_wait_task(&channel->condition,
				[this](WFMailboxTask *task)
			{
				auto *channel = (WFComplexChannel<MSG> *)this->get_request_channel();
				channel->set_state(WFT_STATE_SUCCESS);
				this->ready = true;
			});
			series_of(this)->push_front(this);
			series_of(this)->push_front(waiter);
			this->ready = false;
		}
		break;

	case WFT_STATE_SUCCESS:
		if (channel->get_sending() == false)
		{
			channel->set_sending(true);
			should_send = true;
		}
		else
		{
			waiter = WFCondTaskFactory::create_wait_task(&channel->condition,
				[this](WFMailboxTask *task)
			{
				auto *channel = (WFComplexChannel<MSG> *)this->get_request_channel();
				channel->set_state(WFT_STATE_SUCCESS);
				this->ready = true;
			});
			series_of(this)->push_front(this);
			series_of(this)->push_front(waiter);
			this->ready = false;
		}
		break;

	default:
		this->state = channel->get_state();
		this->error = channel->get_error();
		break;
	}

	pthread_mutex_unlock(&channel->mutex);

	if (should_send == true)
		return this->WFChannelOutTask<MSG>::dispatch();

	return this->subtask_done();
}

template<class MSG>
void ComplexChannelOutTask<MSG>::switch_callback(void *t)
{
	if (this->callback)
		this->callback(this);

	delete this;
}

template<class MSG>
SubTask *ComplexChannelOutTask<MSG>::done()
{
	auto *channel = (WFComplexChannel<MSG> *)this->get_request_channel();

	if (channel->get_state() == WFT_STATE_UNDEFINED ||
		channel->get_state() == WFT_STATE_SUCCESS)
	{
		if (this->ready != true)
			return series_of(this)->pop();
	}
	else
	{
		this->state = channel->get_state();
		this->error = channel->get_error();
	}

	pthread_mutex_lock(&channel->mutex);
	channel->set_sending(false);
	channel->condition.signal(NULL);
	pthread_mutex_unlock(&channel->mutex);

	auto&& cb = std::bind(&ComplexChannelOutTask<MSG>::switch_callback,
						  this,
						  std::placeholders::_1);

	WFTimerTask *timer = WFTaskFactory::create_timer_task(0, 0, std::move(cb));
	series_of(this)->push_front(timer);

	return series_of(this)->pop();
}

template<class MSG>
SubTask *ComplexChannelOutTask<MSG>::upgrade()
{
	WFCounterTask *counter = new WFCounterTask(0, [this](WFCounterTask *task)
	{
		auto *channel = (WFComplexChannel<MSG> *)this->get_request_channel();

		pthread_mutex_lock(&channel->mutex);
		channel->set_state(WFT_STATE_SUCCESS);
		this->ready = true;
		channel->set_sending(false);
		channel->condition.signal(NULL);
		pthread_mutex_unlock(&channel->mutex);
	});

	return counter;
}

/**********WebSocket task impl**********/

class ComplexWebSocketChannel : public WFComplexChannel<protocol::WebSocketFrame>
{
public:
	void set_idle_timeout(int timeout) { this->idle_timeout = timeout; }
	void set_keep_alive(int timeout) { this->keep_alive_timeo = timeout; }
	void set_size_limit(size_t size_limit) { this->size_limit = size_limit; }

	void set_sec_protocol(const char *protocol) { this->sec_protocol = protocol; }
	void set_sec_version(const char *version) { this->sec_version = version; }

	const char *get_sec_protocol() const
	{
		if (!this->sec_protocol.empty())
			return this->sec_protocol.c_str();

		return NULL;
	}

	const char *get_sec_version() const
	{
		if (!this->sec_version.empty())
			return this->sec_version.c_str();

		return NULL;
	}

	uint32_t gen_masking_key()
	{
		if (this->auto_gen_mkey == false)
			return 0;

		return this->gen();
	}

protected:
	virtual CommMessageIn *message_in();
	virtual void handle_in(CommMessageIn *in);
	virtual int first_timeout();
	virtual WFWebSocketTask *new_session();
	virtual int keep_alive_timeout() { return this->keep_alive_timeo; }

private:
	int idle_timeout;
	int keep_alive_timeo;
	size_t size_limit;
	bool auto_gen_mkey; // random Masking-Key
	std::random_device rd;
	std::mt19937 gen;
	std::string sec_protocol; // Sec-WebSocket-Protocol
	std::string sec_version; // Sec-WebSocket-Version

public:
	ComplexWebSocketChannel(CommSchedObject *object,
							CommScheduler *scheduler,
							bool auto_gen_mkey,
							websocket_process_t process) :
		WFComplexChannel<protocol::WebSocketFrame>(object, scheduler,
												   std::move(process)),
		gen(rd())
	{
		this->auto_gen_mkey = auto_gen_mkey;
	}

private:
	bool check_handshake(const protocol::HttpResponse *resp);
};

class ComplexWebSocketOutTask : public ComplexChannelOutTask<protocol::WebSocketFrame>
{
protected:
	virtual SubTask *upgrade();
	virtual SubTask *done();

public:
	ComplexWebSocketOutTask(ComplexWebSocketChannel *channel,
							CommScheduler *scheduler,
							websocket_callback_t&& cb) :
		ComplexChannelOutTask<protocol::WebSocketFrame>(channel,
														scheduler,
														std::move(cb))
	{
	}
};

/**********WFChannelFactory impl**********/

template<class MSG>
WFComplexChannel<MSG> *
WFChannelFactory<MSG>::create_channel(std::function<void (WFChannelTask<MSG> *)> process)
{
	return new WFComplexChannel<MSG>(NULL, WFGlobal::get_scheduler(),
									 std::move(process));
}

template<class MSG>
WFChannelTask<MSG> *
WFChannelFactory<MSG>::create_out_task(WFComplexChannel<MSG> *channel,
									   std::function<void (WFChannelTask<MSG> *)> cb)
{
	return new ComplexChannelOutTask<MSG>(channel, WFGlobal::get_scheduler(),
										  std::move(cb));
}


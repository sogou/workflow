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

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#include <stdio.h>
#include <string>
#include <functional>
#include <utility>
#include <atomic>
#include <openssl/ssl.h>
#include "WFGlobal.h"
#include "Workflow.h"
#include "WFTask.h"
#include "RouteManager.h"
#include "URIParser.h"
#include "WFTaskError.h"
#include "EndpointParams.h"
#include "WFNameService.h"
#include "WFHttpServerTask.h"

class __WFDynamicTask : public WFDynamicTask
{
protected:
	virtual void dispatch()
	{
		series_of(this)->push_front(this->create(this));
		this->WFDynamicTask::dispatch();
	}

protected:
	std::function<SubTask *(WFDynamicTask *)> create;

public:
	__WFDynamicTask(std::function<SubTask *(WFDynamicTask *)>&& create) :
		create(std::move(create))
	{
	}
};

inline WFDynamicTask *
WFTaskFactory::create_dynamic_task(dynamic_create_t create)
{
	return new __WFDynamicTask(std::move(create));
}

template<class REQ, class RESP, typename CTX = bool>
class WFComplexClientTask : public WFClientTask<REQ, RESP>
{
protected:
	using task_callback_t = std::function<void (WFNetworkTask<REQ, RESP> *)>;

public:
	WFComplexClientTask(int retry_max, task_callback_t&& cb):
		WFClientTask<REQ, RESP>(NULL, WFGlobal::get_scheduler(), std::move(cb))
	{
		type_ = TT_TCP;
		ssl_ctx_ = NULL;
		fixed_addr_ = false;
		fixed_conn_ = false;
		retry_max_ = retry_max;
		retry_times_ = 0;
		redirect_ = false;
		ns_policy_ = NULL;
		router_task_ = NULL;
	}

protected:
	// new api for children
	virtual bool init_success() { return true; }
	virtual void init_failed() {}
	virtual bool check_request() { return true; }
	virtual WFRouterTask *route();
	virtual bool finish_once() { return true; }

public:
	void init(const ParsedURI& uri)
	{
		uri_ = uri;
		init_with_uri();
	}

	void init(ParsedURI&& uri)
	{
		uri_ = std::move(uri);
		init_with_uri();
	}

	void init(enum TransportType type,
			  const struct sockaddr *addr,
			  socklen_t addrlen,
			  const std::string& info);

	void set_transport_type(enum TransportType type)
	{
		type_ = type;
	}

	enum TransportType get_transport_type() const { return type_; }

	void set_ssl_ctx(SSL_CTX *ssl_ctx) { ssl_ctx_ = ssl_ctx; }

	virtual const ParsedURI *get_current_uri() const { return &uri_; }

	void set_redirect(const ParsedURI& uri)
	{
		redirect_ = true;
		init(uri);
	}

	void set_redirect(enum TransportType type, const struct sockaddr *addr,
					  socklen_t addrlen, const std::string& info)
	{
		redirect_ = true;
		init(type, addr, addrlen, info);
	}

	bool is_fixed_addr() const { return this->fixed_addr_; }

	bool is_fixed_conn() const { return this->fixed_conn_; }

protected:
	void set_fixed_addr(int fixed) { this->fixed_addr_ = fixed; }

	void set_fixed_conn(int fixed) { this->fixed_conn_ = fixed; }

	void set_info(const std::string& info)
	{
		info_.assign(info);
	}

	void set_info(const char *info)
	{
		info_.assign(info);
	}

protected:
	virtual void dispatch();
	virtual SubTask *done();

	void clear_resp()
	{
		RESP resp;
		*(protocol::ProtocolMessage *)&resp = std::move(this->resp);
		this->resp = std::move(resp);
	}

	void disable_retry()
	{
		retry_times_ = retry_max_;
	}

protected:
	enum TransportType type_;
	ParsedURI uri_;
	std::string info_;
	SSL_CTX *ssl_ctx_;
	bool fixed_addr_;
	bool fixed_conn_;
	bool redirect_;
	CTX ctx_;
	int retry_max_;
	int retry_times_;
	WFNSPolicy *ns_policy_;
	WFRouterTask *router_task_;
	RouteManager::RouteResult route_result_;
	WFNSTracing tracing_;

public:
	CTX *get_mutable_ctx() { return &ctx_; }

private:
	void clear_prev_state();
	void init_with_uri();
	bool set_port();
	void router_callback(void *t);
	void switch_callback(void *t);
};

template<class REQ, class RESP, typename CTX>
void WFComplexClientTask<REQ, RESP, CTX>::clear_prev_state()
{
	ns_policy_ = NULL;
	route_result_.clear();
	if (tracing_.deleter)
	{
		tracing_.deleter(tracing_.data);
		tracing_.deleter = NULL;
	}
	tracing_.data = NULL;
	retry_times_ = 0;
	this->state = WFT_STATE_UNDEFINED;
	this->error = 0;
	this->timeout_reason = TOR_NOT_TIMEOUT;
}

template<class REQ, class RESP, typename CTX>
void WFComplexClientTask<REQ, RESP, CTX>::init(enum TransportType type,
											   const struct sockaddr *addr,
											   socklen_t addrlen,
											   const std::string& info)
{
	if (redirect_)
		clear_prev_state();

	auto params = WFGlobal::get_global_settings()->endpoint_params;
	struct addrinfo addrinfo = { };
	addrinfo.ai_family = addr->sa_family;
	addrinfo.ai_addr = (struct sockaddr *)addr;
	addrinfo.ai_addrlen = addrlen;

	type_ = type;
	info_.assign(info);
	params.use_tls_sni = false;
	if (WFGlobal::get_route_manager()->get(type, &addrinfo, info_, &params,
										   "", ssl_ctx_, route_result_) < 0)
	{
		this->state = WFT_STATE_SYS_ERROR;
		this->error = errno;
	}
	else if (this->init_success())
		return;

	this->init_failed();
}

template<class REQ, class RESP, typename CTX>
bool WFComplexClientTask<REQ, RESP, CTX>::set_port()
{
	if (uri_.port)
	{
		int port = atoi(uri_.port);

		if (port <= 0 || port > 65535)
		{
			this->state = WFT_STATE_TASK_ERROR;
			this->error = WFT_ERR_URI_PORT_INVALID;
			return false;
		}

		return true;
	}

	if (uri_.scheme)
	{
		const char *port_str = WFGlobal::get_default_port(uri_.scheme);

		if (port_str)
		{
			uri_.port = strdup(port_str);
			if (uri_.port)
				return true;

			this->state = WFT_STATE_SYS_ERROR;
			this->error = errno;
			return false;
		}
	}

	this->state = WFT_STATE_TASK_ERROR;
	this->error = WFT_ERR_URI_SCHEME_INVALID;
	return false;
}

template<class REQ, class RESP, typename CTX>
void WFComplexClientTask<REQ, RESP, CTX>::init_with_uri()
{
	if (redirect_)
	{
		clear_prev_state();
		ns_policy_ = WFGlobal::get_dns_resolver();
	}

	if (uri_.state == URI_STATE_SUCCESS)
	{
		if (this->set_port())
		{
			if (this->init_success())
				return;
		}
	}
	else if (uri_.state == URI_STATE_ERROR)
	{
		this->state = WFT_STATE_SYS_ERROR;
		this->error = uri_.error;
	}
	else
	{
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_URI_PARSE_FAILED;
	}

	this->init_failed();
}

template<class REQ, class RESP, typename CTX>
WFRouterTask *WFComplexClientTask<REQ, RESP, CTX>::route()
{
	auto&& cb = std::bind(&WFComplexClientTask::router_callback,
						  this,
						  std::placeholders::_1);
	struct WFNSParams params = {
		.type			=	type_,
		.uri			=	uri_,
		.info			=	info_.c_str(),
		.ssl_ctx		=	ssl_ctx_,
		.fixed_addr		=	fixed_addr_,
		.fixed_conn		=	fixed_conn_,
		.retry_times	=	retry_times_,
		.tracing		=	&tracing_,
	};

	if (!ns_policy_)
	{
		WFNameService *ns = WFGlobal::get_name_service();
		ns_policy_ = ns->get_policy(uri_.host ? uri_.host : "");
	}

	return ns_policy_->create_router_task(&params, std::move(cb));
}

template<class REQ, class RESP, typename CTX>
void WFComplexClientTask<REQ, RESP, CTX>::router_callback(void *t)
{
	WFRouterTask *task = (WFRouterTask *)t;

	this->state = task->get_state();
	if (this->state == WFT_STATE_SUCCESS)
		route_result_ = std::move(*task->get_result());
	else if (this->state == WFT_STATE_UNDEFINED)
	{
		/* should not happend */
		this->state = WFT_STATE_SYS_ERROR;
		this->error = ENOSYS;
	}
	else
		this->error = task->get_error();
}

template<class REQ, class RESP, typename CTX>
void WFComplexClientTask<REQ, RESP, CTX>::dispatch()
{
	switch (this->state)
	{
	case WFT_STATE_UNDEFINED:
		if (this->check_request())
		{
			if (this->route_result_.request_object)
			{
	case WFT_STATE_SUCCESS:
				this->set_request_object(route_result_.request_object);
				this->WFClientTask<REQ, RESP>::dispatch();
				return;
			}

			router_task_ = this->route();
			series_of(this)->push_front(this);
			series_of(this)->push_front(router_task_);
		}

	default:
		break;
	}

	this->subtask_done();
}

template<class REQ, class RESP, typename CTX>
void WFComplexClientTask<REQ, RESP, CTX>::switch_callback(void *t)
{
	if (!redirect_)
	{
		if (this->state == WFT_STATE_SYS_ERROR && this->error < 0)
		{
			this->state = WFT_STATE_SSL_ERROR;
			this->error = -this->error;
		}

		if (tracing_.deleter)
		{
			tracing_.deleter(tracing_.data);
			tracing_.deleter = NULL;
		}

		if (this->callback)
			this->callback(this);
	}

	if (redirect_)
	{
		redirect_ = false;
		clear_resp();
		this->target = NULL;
		series_of(this)->push_front(this);
	}
	else
		delete this;
}

template<class REQ, class RESP, typename CTX>
SubTask *WFComplexClientTask<REQ, RESP, CTX>::done()
{
	SeriesWork *series = series_of(this);

	if (router_task_)
	{
		router_task_ = NULL;
		return series->pop();
	}

	bool is_user_request = this->finish_once();

	if (ns_policy_)
	{
		if (this->state == WFT_STATE_SYS_ERROR ||
			this->state == WFT_STATE_DNS_ERROR)
		{
			ns_policy_->failed(&route_result_, &tracing_, this->target);
		}
		else if (route_result_.request_object)
		{
			ns_policy_->success(&route_result_, &tracing_, this->target);
		}
	}

	if (this->state == WFT_STATE_SUCCESS)
	{
		if (!is_user_request)
			return this;
	}
	else if (this->state == WFT_STATE_SYS_ERROR)
	{
		if (retry_times_ < retry_max_)
		{
			redirect_ = true;
			if (ns_policy_)
				route_result_.clear();

			this->state = WFT_STATE_UNDEFINED;
			this->error = 0;
			this->timeout_reason = 0;
			retry_times_++;
		}
	}

	/* When the target or the connection is NULL, it's very likely that we are
	 * in the caller's thread. Running a timer will switch callback function to
	 * a handler thread, and this can prevent stack overflow. */
	if (!this->target || !this->CommSession::get_connection())
	{
		auto&& cb = std::bind(&WFComplexClientTask::switch_callback,
							  this,
							  std::placeholders::_1);
		WFTimerTask *timer;

		timer = WFTaskFactory::create_timer_task(0, 0, std::move(cb));
		series->push_front(timer);
	}
	else
		this->switch_callback(NULL);

	return series->pop();
}

/**********Template Network Factory**********/

template<class REQ, class RESP>
WFNetworkTask<REQ, RESP> *
WFNetworkTaskFactory<REQ, RESP>::create_client_task(enum TransportType type,
													const std::string& host,
													unsigned short port,
													int retry_max,
													std::function<void (WFNetworkTask<REQ, RESP> *)> callback)
{
	auto *task = new WFComplexClientTask<REQ, RESP>(retry_max, std::move(callback));
	ParsedURI uri;
	char buf[32];

	sprintf(buf, "%u", port);
	uri.scheme = strdup("scheme");
	uri.host = strdup(host.c_str());
	uri.port = strdup(buf);
	if (!uri.scheme || !uri.host || !uri.port)
	{
		uri.state = URI_STATE_ERROR;
		uri.error = errno;
	}
	else
		uri.state = URI_STATE_SUCCESS;

	task->init(std::move(uri));
	task->set_transport_type(type);
	return task;
}

template<class REQ, class RESP>
WFNetworkTask<REQ, RESP> *
WFNetworkTaskFactory<REQ, RESP>::create_client_task(enum TransportType type,
													const std::string& url,
													int retry_max,
													std::function<void (WFNetworkTask<REQ, RESP> *)> callback)
{
	auto *task = new WFComplexClientTask<REQ, RESP>(retry_max, std::move(callback));
	ParsedURI uri;

	URIParser::parse(url, uri);
	task->init(std::move(uri));
	task->set_transport_type(type);
	return task;
}

template<class REQ, class RESP>
WFNetworkTask<REQ, RESP> *
WFNetworkTaskFactory<REQ, RESP>::create_client_task(enum TransportType type,
													const ParsedURI& uri,
													int retry_max,
													std::function<void (WFNetworkTask<REQ, RESP> *)> callback)
{
	auto *task = new WFComplexClientTask<REQ, RESP>(retry_max, std::move(callback));

	task->init(uri);
	task->set_transport_type(type);
	return task;
}

template<class REQ, class RESP>
WFNetworkTask<REQ, RESP> *
WFNetworkTaskFactory<REQ, RESP>::create_client_task(enum TransportType type,
													const struct sockaddr *addr,
													socklen_t addrlen,
													int retry_max,
													std::function<void (WFNetworkTask<REQ, RESP> *)> callback)
{
	auto *task = new WFComplexClientTask<REQ, RESP>(retry_max, std::move(callback));

	task->init(type, addr, addrlen, "");
	return task;
}

template<class REQ, class RESP>
WFNetworkTask<REQ, RESP> *
WFNetworkTaskFactory<REQ, RESP>::create_client_task(enum TransportType type,
													const struct sockaddr *addr,
													socklen_t addrlen,
													SSL_CTX *ssl_ctx,
													int retry_max,
													std::function<void (WFNetworkTask<REQ, RESP> *)> callback)
{
	auto *task = new WFComplexClientTask<REQ, RESP>(retry_max, std::move(callback));

	task->set_ssl_ctx(ssl_ctx);
	task->init(type, addr, addrlen, "");
	return task;
}

template<class REQ, class RESP>
WFNetworkTask<REQ, RESP> *
WFNetworkTaskFactory<REQ, RESP>::create_server_task(CommService *service,
				std::function<void (WFNetworkTask<REQ, RESP> *)>& proc)
{
	return new WFServerTask<REQ, RESP>(service, WFGlobal::get_scheduler(), proc);
}

/**********Server Factory**********/

class WFServerTaskFactory
{
public:
	static WFDnsTask *create_dns_task(CommService *service,
					std::function<void (WFDnsTask *)>& proc);

	static WFHttpTask *create_http_task(CommService *service,
					std::function<void (WFHttpTask *)>& proc)
	{
		return new WFHttpServerTask(service, proc);
	}

	static WFMySQLTask *create_mysql_task(CommService *service,
					std::function<void (WFMySQLTask *)>& proc);
};

/************Go Task Factory************/

class __WFGoTask : public WFGoTask
{
public:
	void set_go_func(std::function<void ()> func)
	{
		this->go = std::move(func);
	}

protected:
	virtual void execute()
	{
		this->go();
	}

protected:
	std::function<void ()> go;

public:
	__WFGoTask(ExecQueue *queue, Executor *executor,
			   std::function<void ()>&& func) :
		WFGoTask(queue, executor),
		go(std::move(func))
	{
	}
};

class __WFTimedGoTask : public __WFGoTask
{
protected:
	virtual void dispatch();
	virtual SubTask *done();

protected:
	virtual void handle(int state, int error);

protected:
	static void timer_callback(WFTimerTask *timer);

protected:
	time_t seconds;
	long nanoseconds;
	std::atomic<int> ref;

public:
	__WFTimedGoTask(time_t seconds, long nanoseconds,
					ExecQueue *queue, Executor *executor,
					std::function<void ()>&& func) :
		__WFGoTask(queue, executor, std::move(func)),
		ref(4)
	{
		this->seconds = seconds;
		this->nanoseconds = nanoseconds;
	}
};

template<class FUNC, class... ARGS>
WFGoTask *WFTaskFactory::create_go_task(const std::string& queue_name,
										FUNC&& func, ARGS&&... args)
{
	auto&& tmp = std::bind(std::forward<FUNC>(func),
						   std::forward<ARGS>(args)...);
	return new __WFGoTask(WFGlobal::get_exec_queue(queue_name),
						  WFGlobal::get_compute_executor(),
						  std::move(tmp));
}

template<class FUNC, class... ARGS>
WFGoTask *WFTaskFactory::create_timedgo_task(time_t seconds, long nanoseconds,
											 const std::string& queue_name,
											 FUNC&& func, ARGS&&... args)
{
	auto&& tmp = std::bind(std::forward<FUNC>(func),
						   std::forward<ARGS>(args)...);
	return new __WFTimedGoTask(seconds, nanoseconds,
							   WFGlobal::get_exec_queue(queue_name),
							   WFGlobal::get_compute_executor(),
							   std::move(tmp));
}

template<class FUNC, class... ARGS>
WFGoTask *WFTaskFactory::create_go_task(ExecQueue *queue, Executor *executor,
										FUNC&& func, ARGS&&... args)
{
	auto&& tmp = std::bind(std::forward<FUNC>(func),
						   std::forward<ARGS>(args)...);
	return new __WFGoTask(queue, executor, std::move(tmp));
}

template<class FUNC, class... ARGS>
WFGoTask *WFTaskFactory::create_timedgo_task(time_t seconds, long nanoseconds,
											 ExecQueue *queue, Executor *executor,
											 FUNC&& func, ARGS&&... args)
{
	auto&& tmp = std::bind(std::forward<FUNC>(func),
						   std::forward<ARGS>(args)...);
	return new __WFTimedGoTask(seconds, nanoseconds,
							   queue, executor,
							   std::move(tmp));
}

template<class FUNC, class... ARGS>
void WFTaskFactory::reset_go_task(WFGoTask *task, FUNC&& func, ARGS&&... args)
{
	auto&& tmp = std::bind(std::forward<FUNC>(func),
						   std::forward<ARGS>(args)...);
	((__WFGoTask *)task)->set_go_func(std::move(tmp));
}

/**********Create go task with nullptr func**********/

template<> inline
WFGoTask *WFTaskFactory::create_go_task(const std::string& queue_name,
										std::nullptr_t&& func)
{
	return new __WFGoTask(WFGlobal::get_exec_queue(queue_name),
						  WFGlobal::get_compute_executor(),
						  nullptr);
}

template<> inline
WFGoTask *WFTaskFactory::create_timedgo_task(time_t seconds, long nanoseconds,
											 const std::string& queue_name,
											 std::nullptr_t&& func)
{
	return new __WFTimedGoTask(seconds, nanoseconds,
							   WFGlobal::get_exec_queue(queue_name),
							   WFGlobal::get_compute_executor(),
							   nullptr);
}

template<> inline
WFGoTask *WFTaskFactory::create_go_task(ExecQueue *queue, Executor *executor,
										std::nullptr_t&& func)
{
	return new __WFGoTask(queue, executor, nullptr);
}

template<> inline
WFGoTask *WFTaskFactory::create_timedgo_task(time_t seconds, long nanoseconds,
											 ExecQueue *queue, Executor *executor,
											 std::nullptr_t&& func)
{
	return new __WFTimedGoTask(seconds, nanoseconds, queue, executor, nullptr);
}

template<> inline
void WFTaskFactory::reset_go_task(WFGoTask *task, std::nullptr_t&& func)
{
	((__WFGoTask *)task)->set_go_func(nullptr);
}

/**********Template Thread Task Factory**********/

template<class INPUT, class OUTPUT>
class __WFThreadTask : public WFThreadTask<INPUT, OUTPUT>
{
protected:
	virtual void execute()
	{
		this->routine(&this->input, &this->output);
	}

protected:
	std::function<void (INPUT *, OUTPUT *)> routine;

public:
	__WFThreadTask(ExecQueue *queue, Executor *executor,
				   std::function<void (INPUT *, OUTPUT *)>&& rt,
				   std::function<void (WFThreadTask<INPUT, OUTPUT> *)>&& cb) :
		WFThreadTask<INPUT, OUTPUT>(queue, executor, std::move(cb)),
		routine(std::move(rt))
	{
	}
};

template<class INPUT, class OUTPUT>
class __WFTimedThreadTask : public __WFThreadTask<INPUT, OUTPUT>
{
protected:
	virtual void dispatch();
	virtual SubTask *done();

protected:
	virtual void handle(int state, int error);

protected:
	static void timer_callback(WFTimerTask *timer);

protected:
	time_t seconds;
	long nanoseconds;
	std::atomic<int> ref;

public:
	__WFTimedThreadTask(time_t seconds, long nanoseconds,
						ExecQueue *queue, Executor *executor,
						std::function<void (INPUT *, OUTPUT *)>&& rt,
						std::function<void (WFThreadTask<INPUT, OUTPUT> *)>&& cb) :
		__WFThreadTask<INPUT, OUTPUT>(queue, executor, std::move(rt), std::move(cb)),
		ref(4)
	{
		this->seconds = seconds;
		this->nanoseconds = nanoseconds;
	}
};

template<class INPUT, class OUTPUT>
void __WFTimedThreadTask<INPUT, OUTPUT>::dispatch()
{
	WFTimerTask *timer;

	timer = WFTaskFactory::create_timer_task(this->seconds, this->nanoseconds,
											 __WFTimedThreadTask::timer_callback);
	timer->user_data = this;

	this->__WFThreadTask<INPUT, OUTPUT>::dispatch();
	timer->start();
}

template<class INPUT, class OUTPUT>
SubTask *__WFTimedThreadTask<INPUT, OUTPUT>::done()
{
	if (this->callback)
		this->callback(this);

	return series_of(this)->pop();
}

template<class INPUT, class OUTPUT>
void __WFTimedThreadTask<INPUT, OUTPUT>::handle(int state, int error)
{
	if (--this->ref == 3)
	{
		this->state = state;
		this->error = error;
		this->subtask_done();
	}

	if (--this->ref == 0)
		delete this;
}

template<class INPUT, class OUTPUT>
void __WFTimedThreadTask<INPUT, OUTPUT>::timer_callback(WFTimerTask *timer)
{
	auto *task = (__WFTimedThreadTask<INPUT, OUTPUT> *)timer->user_data;

	if (--task->ref == 3)
	{
		if (timer->get_state() == WFT_STATE_SUCCESS)
		{
			task->state = WFT_STATE_SYS_ERROR;
			task->error = ETIMEDOUT;
		}
		else
		{
			task->state = timer->get_state();
			task->error = timer->get_error();
		}

		task->subtask_done();
	}

	if (--task->ref == 0)
		delete task;
}

template<class INPUT, class OUTPUT>
WFThreadTask<INPUT, OUTPUT> *
WFThreadTaskFactory<INPUT, OUTPUT>::create_thread_task(const std::string& queue_name,
						std::function<void (INPUT *, OUTPUT *)> routine,
						std::function<void (WFThreadTask<INPUT, OUTPUT> *)> callback)
{
	return new __WFThreadTask<INPUT, OUTPUT>(WFGlobal::get_exec_queue(queue_name),
											 WFGlobal::get_compute_executor(),
											 std::move(routine),
											 std::move(callback));
}

template<class INPUT, class OUTPUT>
WFThreadTask<INPUT, OUTPUT> *
WFThreadTaskFactory<INPUT, OUTPUT>::create_thread_task(time_t seconds, long nanoseconds,
						const std::string& queue_name,
						std::function<void (INPUT *, OUTPUT *)> routine,
						std::function<void (WFThreadTask<INPUT, OUTPUT> *)> callback)
{
	return new __WFTimedThreadTask<INPUT, OUTPUT>(seconds, nanoseconds,
												  WFGlobal::get_exec_queue(queue_name),
												  WFGlobal::get_compute_executor(),
												  std::move(routine),
												  std::move(callback));
}

template<class INPUT, class OUTPUT>
WFThreadTask<INPUT, OUTPUT> *
WFThreadTaskFactory<INPUT, OUTPUT>::create_thread_task(ExecQueue *queue, Executor *executor,
						std::function<void (INPUT *, OUTPUT *)> routine,
						std::function<void (WFThreadTask<INPUT, OUTPUT> *)> callback)
{
	return new __WFThreadTask<INPUT, OUTPUT>(queue, executor,
											 std::move(routine),
											 std::move(callback));
}

template<class INPUT, class OUTPUT>
WFThreadTask<INPUT, OUTPUT> *
WFThreadTaskFactory<INPUT, OUTPUT>::create_thread_task(time_t seconds, long nanoseconds,
						ExecQueue *queue, Executor *executor,
						std::function<void (INPUT *, OUTPUT *)> routine,
						std::function<void (WFThreadTask<INPUT, OUTPUT> *)> callback)
{
	return new __WFTimedThreadTask<INPUT, OUTPUT>(seconds, nanoseconds,
												  queue, executor,
												  std::move(routine),
												  std::move(callback));
}


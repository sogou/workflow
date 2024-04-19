/*
  Copyright (c) 2020 Sogou, Inc.

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
           Liu Kai (liukaidx@sogou-inc.com)
           Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <utility>
#include <string>
#include "EndpointParams.h"
#include "RouteManager.h"
#include "WFGlobal.h"
#include "WFTaskFactory.h"
#include "WFResourcePool.h"
#include "WFNameService.h"
#include "DnsCache.h"
#include "DnsUtil.h"
#include "WFDnsClient.h"
#include "WFDnsResolver.h"

#define HOSTS_LINEBUF_INIT_SIZE	128
#define PORT_STR_MAX			5

class DnsInput
{
public:
	DnsInput() :
		port_(0),
		numeric_host_(false),
		family_(AF_UNSPEC)
	{}

	DnsInput(const std::string& host, unsigned short port,
			 bool numeric_host, int family) :
		host_(host),
		port_(port),
		numeric_host_(numeric_host),
		family_(family)
	{}

	void reset(const std::string& host, unsigned short port)
	{
		host_.assign(host);
		port_ = port;
		numeric_host_ = false;
		family_ = AF_UNSPEC;
	}

	void reset(const std::string& host, unsigned short port,
			   bool numeric_host, int family)
	{
		host_.assign(host);
		port_ = port;
		numeric_host_ = numeric_host;
		family_ = family;
	}

	const std::string& get_host() const { return host_; }
	unsigned short get_port() const { return port_; }
	bool is_numeric_host() const { return numeric_host_; }

protected:
	std::string host_;
	unsigned short port_;
	bool numeric_host_;
	int family_;

	friend class DnsRoutine;
};

class DnsOutput
{
public:
	DnsOutput():
		error_(0),
		addrinfo_(NULL)
	{}

	~DnsOutput()
	{
		if (addrinfo_)
		{
			if (addrinfo_->ai_flags)
				freeaddrinfo(addrinfo_);
			else
				free(addrinfo_);
		}
	}

	int get_error() const { return error_; }
	const struct addrinfo *get_addrinfo() const { return addrinfo_; }

	//if DONOT want DnsOutput release addrinfo, use move_addrinfo in callback
	struct addrinfo *move_addrinfo()
	{
		struct addrinfo *p = addrinfo_;
		addrinfo_ = NULL;
		return p;
	}

protected:
	int error_;
	struct addrinfo *addrinfo_;

	friend class DnsRoutine;
};

class DnsRoutine
{
public:
	static void run(const DnsInput *in, DnsOutput *out);
	static void create(DnsOutput *out, int error, struct addrinfo *ai)
	{
		if (out->addrinfo_)
		{
			if (out->addrinfo_->ai_flags)
				freeaddrinfo(out->addrinfo_);
			else
				free(out->addrinfo_);
		}

		out->error_ = error;
		out->addrinfo_ = ai;
	}

private:
	static void run_local_path(const std::string& path, DnsOutput *out);
};

void DnsRoutine::run_local_path(const std::string& path, DnsOutput *out)
{
	struct sockaddr_un *sun = NULL;

	if (path.size() + 1 <= sizeof sun->sun_path)
	{
		size_t size = sizeof (struct addrinfo) + sizeof (struct sockaddr_un);

		out->addrinfo_ = (struct addrinfo *)calloc(size, 1);
		if (out->addrinfo_)
		{
			sun = (struct sockaddr_un *)(out->addrinfo_ + 1);
			sun->sun_family = AF_UNIX;
			memcpy(sun->sun_path, path.c_str(), path.size());

			out->addrinfo_->ai_family = AF_UNIX;
			out->addrinfo_->ai_socktype = SOCK_STREAM;
			out->addrinfo_->ai_addr = (struct sockaddr *)sun;
			size = offsetof(struct sockaddr_un, sun_path) + path.size() + 1;
			out->addrinfo_->ai_addrlen = size;
			out->error_ = 0;
			return;
		}
	}
	else
		errno = EINVAL;

	out->error_ = EAI_SYSTEM;
}

void DnsRoutine::run(const DnsInput *in, DnsOutput *out)
{
	if (in->host_[0] == '/')
	{
		run_local_path(in->host_, out);
		return;
	}

	struct addrinfo hints = {
		.ai_flags		=	AI_ADDRCONFIG | AI_NUMERICSERV,
		.ai_family		=	in->family_,
		.ai_socktype	=	SOCK_STREAM,
	};
	char port_str[PORT_STR_MAX + 1];

	if (in->is_numeric_host())
		hints.ai_flags |= AI_NUMERICHOST;

	snprintf(port_str, PORT_STR_MAX + 1, "%u", in->port_);
	out->error_ = getaddrinfo(in->host_.c_str(), port_str,
							  &hints, &out->addrinfo_);
	if (out->error_ == 0)
		out->addrinfo_->ai_flags = 1;
}

// Dns Thread task. For internal usage only.
using ThreadDnsTask = WFThreadTask<DnsInput, DnsOutput>;
using thread_dns_callback_t = std::function<void (ThreadDnsTask *)>;

struct DnsContext
{
	int state;
	int error;
	int eai_error;
	unsigned short port;
	struct addrinfo *ai;
};

static int __default_family()
{
	struct addrinfo hints = {
		.ai_flags		=	AI_ADDRCONFIG,
		.ai_family		=	AF_UNSPEC,
		.ai_socktype	=	SOCK_STREAM,
	};
	struct addrinfo *res;
	struct addrinfo *cur;
	int family = AF_UNSPEC;
	bool v4 = false;
	bool v6 = false;

	if (getaddrinfo(NULL, "1", &hints, &res) == 0)
	{
		for (cur = res; cur; cur = cur->ai_next)
		{
			if (cur->ai_family == AF_INET)
				v4 = true;
			else if (cur->ai_family == AF_INET6)
				v6 = true;
		}

		freeaddrinfo(res);
		if (v4 ^ v6)
			family = v4 ? AF_INET : AF_INET6;
	}

	return family;
}

// hosts line format: IP canonical_name [aliases...] [# Comment]
static int __readaddrinfo_line(char *p, const char *name, const char *port,
							   const struct addrinfo *hints,
							   struct addrinfo **res)
{
	const char *ip = NULL;
	char *start;

	start = p;
	while (*start != '\0' && *start != '#')
		start++;
	*start = '\0';

	while (1)
	{
		while (isspace(*p))
			p++;

		start = p;
		while (*p != '\0' && !isspace(*p))
			p++;

		if (start == p)
			break;

		if (*p != '\0')
			*p++ = '\0';

		if (ip == NULL)
		{
			ip = start;
			continue;
		}

		if (strcasecmp(name, start) == 0)
		{
			if (getaddrinfo(ip, port, hints, res) == 0)
				return 0;
		}
	}

	return 1;
}

static int __readaddrinfo(const char *path,
						  const char *name, unsigned short port,
						  const struct addrinfo *hints,
						  struct addrinfo **res)
{
	char port_str[PORT_STR_MAX + 1];
	size_t bufsize = 0;
	char *line = NULL;
	int count = 0;
	int errno_bak;
	FILE *fp;
	int ret;

	fp = fopen(path, "r");
	if (!fp)
		return EAI_SYSTEM;

	snprintf(port_str, PORT_STR_MAX + 1, "%u", port);

	errno_bak = errno;
	while ((ret = getline(&line, &bufsize, fp)) > 0)
	{
		if (__readaddrinfo_line(line, name, port_str, hints, res) == 0)
		{
			count++;
			res = &(*res)->ai_next;
		}
	}

	ret = ferror(fp) ? EAI_SYSTEM : EAI_NONAME;
	free(line);
	fclose(fp);
	if (count != 0)
	{
		errno = errno_bak;
		return 0;
	}

	return ret;
}

static ThreadDnsTask *__create_thread_dns_task(const std::string& host,
											   unsigned short port,
											   int family,
											   thread_dns_callback_t callback)
{
	auto *task = WFThreadTaskFactory<DnsInput, DnsOutput>::
						create_thread_task(WFGlobal::get_dns_queue(),
										   WFGlobal::get_dns_executor(),
										   DnsRoutine::run,
										   std::move(callback));

	task->get_input()->reset(host, port, false, family);
	return task;
}

static std::string __get_cache_host(const std::string& hostname,
									int family)
{
	char c;

	if (family == AF_UNSPEC)
		c = '*';
	else if (family == AF_INET)
		c = '4';
	else if (family == AF_INET6)
		c = '6';
	else
		c = '?';

	return hostname + c;
}

static std::string __get_guard_name(const std::string& cache_host,
									unsigned short port)
{
	std::string guard_name("INTERNAL-dns:");
	guard_name.append(cache_host).append(":");
	guard_name.append(std::to_string(port));
	return guard_name;
}

void WFResolverTask::dispatch()
{
	if (this->msg_)
	{
		this->state = WFT_STATE_DNS_ERROR;
		this->error = (intptr_t)msg_;
		this->subtask_done();
		return;
	}

	const ParsedURI& uri = ns_params_.uri;
	host_ = uri.host ? uri.host : "";
	port_ = uri.port ? atoi(uri.port) : 0;

	DnsCache *dns_cache = WFGlobal::get_dns_cache();
	const DnsCache::DnsHandle *addr_handle;
	std::string hostname = host_;
	int family = ep_params_.address_family;
	std::string cache_host = __get_cache_host(hostname, family);

	if (ns_params_.retry_times == 0)
		addr_handle = dns_cache->get_ttl(cache_host, port_);
	else
		addr_handle = dns_cache->get_confident(cache_host, port_);

	if (in_guard_ && (addr_handle == NULL || addr_handle->value.delayed()))
	{
		if (addr_handle)
			dns_cache->release(addr_handle);

		this->request_dns();
		return;
	}

	if (addr_handle)
	{
		RouteManager *route_manager = WFGlobal::get_route_manager();
		struct addrinfo *addrinfo = addr_handle->value.addrinfo;
		struct addrinfo first;

		if (ns_params_.fixed_addr && addrinfo->ai_next)
		{
			first = *addrinfo;
			first.ai_next = NULL;
			addrinfo = &first;
		}

		if (route_manager->get(ns_params_.type, addrinfo, ns_params_.info,
							   &ep_params_, hostname, ns_params_.ssl_ctx,
							   this->result) < 0)
		{
			this->state = WFT_STATE_SYS_ERROR;
			this->error = errno;
		}
		else
			this->state = WFT_STATE_SUCCESS;

		dns_cache->release(addr_handle);
		this->subtask_done();
		return;
	}

	if (*host_)
	{
		char front = host_[0];
		char back = host_[hostname.size() - 1];
		struct in6_addr addr;
		int ret;

		if (strchr(host_, ':'))
			ret = inet_pton(AF_INET6, host_, &addr);
		else if (isdigit(back) && isdigit(front))
			ret = inet_pton(AF_INET, host_, &addr);
		else if (front == '/')
			ret = 1;
		else
			ret = 0;

		if (ret == 1)
		{
			// 'true' means numeric host
			DnsInput dns_in(hostname, port_, true, AF_UNSPEC);
			DnsOutput dns_out;

			DnsRoutine::run(&dns_in, &dns_out);
			dns_callback_internal(&dns_out, (unsigned int)-1, (unsigned int)-1);
			this->subtask_done();
			return;
		}
	}

	const char *hosts = WFGlobal::get_global_settings()->hosts_path;
	if (hosts)
	{
		struct addrinfo hints = {
			.ai_flags		=	AI_ADDRCONFIG | AI_NUMERICSERV | AI_NUMERICHOST,
			.ai_family		=	ep_params_.address_family,
			.ai_socktype	=	SOCK_STREAM,
		};
		struct addrinfo *ai;
		int ret;

		ret = __readaddrinfo(hosts, host_, port_, &hints, &ai);
		if (ret == 0)
		{
			DnsOutput out;
			DnsRoutine::create(&out, ret, ai);
			dns_callback_internal(&out, dns_ttl_default_, dns_ttl_min_);
			this->subtask_done();
			return;
		}
	}

	std::string guard_name = __get_guard_name(cache_host, port_);
	WFConditional *guard = WFTaskFactory::create_guard(guard_name, this, &msg_);

	in_guard_ = true;
	has_next_ = true;

	series_of(this)->push_front(guard);
	this->subtask_done();
}

void WFResolverTask::request_dns()
{
	WFDnsClient *client = WFGlobal::get_dns_client();
	if (client)
	{
		static int default_family = __default_family();
		WFResourcePool *respool = WFGlobal::get_dns_respool();

		int family = ep_params_.address_family;
		if (family == AF_UNSPEC)
			family = default_family;

		if (family == AF_INET || family == AF_INET6)
		{
			auto&& cb = std::bind(&WFResolverTask::dns_single_callback,
								  this,
								  std::placeholders::_1);
			WFDnsTask *dns_task = client->create_dns_task(host_, std::move(cb));

			if (family == AF_INET6)
				dns_task->get_req()->set_question_type(DNS_TYPE_AAAA);

			WFConditional *cond = respool->get(dns_task);
			series_of(this)->push_front(cond);
		}
		else
		{
			struct DnsContext *dctx = new struct DnsContext[2];
			WFDnsTask *task_v4;
			WFDnsTask *task_v6;
			ParallelWork *pwork;

			dctx[0].ai = NULL;
			dctx[1].ai = NULL;
			dctx[0].port = port_;
			dctx[1].port = port_;

			task_v4 = client->create_dns_task(host_, dns_partial_callback);
			task_v4->user_data = dctx;

			task_v6 = client->create_dns_task(host_, dns_partial_callback);
			task_v6->get_req()->set_question_type(DNS_TYPE_AAAA);
			task_v6->user_data = dctx + 1;

			auto&& cb = std::bind(&WFResolverTask::dns_parallel_callback,
								  this,
								  std::placeholders::_1);

			pwork = Workflow::create_parallel_work(std::move(cb));
			pwork->set_context(dctx);

			WFConditional *cond_v4 = respool->get(task_v4);
			WFConditional *cond_v6 = respool->get(task_v6);
			pwork->add_series(Workflow::create_series_work(cond_v4, nullptr));
			pwork->add_series(Workflow::create_series_work(cond_v6, nullptr));

			series_of(this)->push_front(pwork);
		}
	}
	else
	{
		ThreadDnsTask *dns_task;
		auto&& cb = std::bind(&WFResolverTask::thread_dns_callback,
							  this,
							  std::placeholders::_1);
		dns_task = __create_thread_dns_task(host_, port_,
											ep_params_.address_family,
											std::move(cb));
		series_of(this)->push_front(dns_task);
	}

	has_next_ = true;
	this->subtask_done();
}

SubTask *WFResolverTask::done()
{
	SeriesWork *series = series_of(this);

	if (!has_next_)
		task_callback();
	else
		has_next_ = false;

	return series->pop();
}

void WFResolverTask::dns_callback_internal(void *thrd_dns_output,
										   unsigned int ttl_default,
										   unsigned int ttl_min)
{
	DnsOutput *dns_out = (DnsOutput *)thrd_dns_output;
	int dns_error = dns_out->get_error();

	if (dns_error)
	{
		if (dns_error == EAI_SYSTEM)
		{
			this->state = WFT_STATE_SYS_ERROR;
			this->error = errno;
		}
		else
		{
			this->state = WFT_STATE_DNS_ERROR;
			this->error = dns_error;
		}
	}
	else
	{
		RouteManager *route_manager = WFGlobal::get_route_manager();
		DnsCache *dns_cache = WFGlobal::get_dns_cache();
		struct addrinfo *addrinfo = dns_out->move_addrinfo();
		const DnsCache::DnsHandle *addr_handle;
		std::string hostname = host_;
		int family = ep_params_.address_family;
		std::string cache_host = __get_cache_host(hostname, family);

		addr_handle = dns_cache->put(cache_host, port_, addrinfo,
									 (unsigned int)ttl_default,
									 (unsigned int)ttl_min);
		if (route_manager->get(ns_params_.type, addrinfo, ns_params_.info,
							   &ep_params_, hostname, ns_params_.ssl_ctx,
							   this->result) < 0)
		{
			this->state = WFT_STATE_SYS_ERROR;
			this->error = errno;
		}
		else
			this->state = WFT_STATE_SUCCESS;

		dns_cache->release(addr_handle);
	}
}

void WFResolverTask::dns_single_callback(void *net_dns_task)
{
	WFDnsTask *dns_task = (WFDnsTask *)net_dns_task;
	WFGlobal::get_dns_respool()->post(NULL);

	if (dns_task->get_state() == WFT_STATE_SUCCESS)
	{
		struct addrinfo *ai = NULL;
		int ret;

		ret = protocol::DnsUtil::getaddrinfo(dns_task->get_resp(), port_, &ai);
		DnsOutput out;
		DnsRoutine::create(&out, ret, ai);
		dns_callback_internal(&out, dns_ttl_default_, dns_ttl_min_);
	}
	else
	{
		this->state = dns_task->get_state();
		this->error = dns_task->get_error();
	}

	task_callback();
}

void WFResolverTask::dns_partial_callback(void *net_dns_task)
{
	WFDnsTask *dns_task = (WFDnsTask *)net_dns_task;
	WFGlobal::get_dns_respool()->post(NULL);

	struct DnsContext *ctx = (struct DnsContext *)dns_task->user_data;
	ctx->ai = NULL;
	ctx->state = dns_task->get_state();
	ctx->error = dns_task->get_error();
	if (ctx->state == WFT_STATE_SUCCESS)
	{
		protocol::DnsResponse *resp = dns_task->get_resp();
		ctx->eai_error = protocol::DnsUtil::getaddrinfo(resp, ctx->port,
														&ctx->ai);
	}
	else
		ctx->eai_error = EAI_NONAME;
}

void WFResolverTask::dns_parallel_callback(const void *parallel)
{
	const ParallelWork *pwork = (const ParallelWork *)parallel;
	struct DnsContext *c4 = (struct DnsContext *)(pwork->get_context());
	struct DnsContext *c6 = c4 + 1;
	DnsOutput out;

	if (c4->state != WFT_STATE_SUCCESS && c6->state != WFT_STATE_SUCCESS)
	{
		this->state = c4->state;
		this->error = c4->error;
	}
	else if (c4->eai_error != 0 && c6->eai_error != 0)
	{
		DnsRoutine::create(&out, c4->eai_error, NULL);
		dns_callback_internal(&out, dns_ttl_default_, dns_ttl_min_);
	}
	else
	{
		struct addrinfo *ai = NULL;
		struct addrinfo **pai = &ai;

		if (c4->ai != NULL)
		{
			*pai = c4->ai;
			while (*pai)
				pai = &(*pai)->ai_next;
		}

		if (c6->ai != NULL)
			*pai = c6->ai;

		DnsRoutine::create(&out, 0, ai);
		dns_callback_internal(&out, dns_ttl_default_, dns_ttl_min_);
	}

	delete[] c4;

	task_callback();
}

void WFResolverTask::thread_dns_callback(void *thrd_dns_task)
{
	ThreadDnsTask *dns_task = (ThreadDnsTask *)thrd_dns_task;

	if (dns_task->get_state() == WFT_STATE_SUCCESS)
	{
		DnsOutput *out = dns_task->get_output();
		dns_callback_internal(out, dns_ttl_default_, dns_ttl_min_);
	}
	else
	{
		this->state = dns_task->get_state();
		this->error = dns_task->get_error();
	}

	task_callback();
}

void WFResolverTask::task_callback()
{
	if (in_guard_)
	{
		int family = ep_params_.address_family;
		std::string cache_host = __get_cache_host(host_, family);
		std::string guard_name = __get_guard_name(cache_host, port_);

		if (this->state == WFT_STATE_DNS_ERROR)
			msg_ = (void *)(intptr_t)this->error;

		WFTaskFactory::release_guard_safe(guard_name, msg_);
	}

	if (this->callback)
		this->callback(this);

	delete this;
}

WFRouterTask *WFDnsResolver::create_router_task(const struct WFNSParams *params,
												router_callback_t callback)
{
	const struct WFGlobalSettings *settings = WFGlobal::get_global_settings();
	unsigned int dns_ttl_default = settings->dns_ttl_default;
	unsigned int dns_ttl_min = settings->dns_ttl_min;
	const struct EndpointParams *ep_params = &settings->endpoint_params;
	return new WFResolverTask(params, dns_ttl_default, dns_ttl_min, ep_params,
							  std::move(callback));
}


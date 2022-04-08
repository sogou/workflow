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
#include <ctype.h>
#include <utility>
#include <string>
#include "DnsRoutine.h"
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

/*
DNS_CACHE_LEVEL_0	->	NO cache
DNS_CACHE_LEVEL_1	->	TTL MIN
DNS_CACHE_LEVEL_2	->	TTL [DEFAULT]
DNS_CACHE_LEVEL_3	->	Forever
*/

#define DNS_CACHE_LEVEL_0		0
#define DNS_CACHE_LEVEL_1		1
#define DNS_CACHE_LEVEL_2		2
#define DNS_CACHE_LEVEL_3		3

#define HOSTS_LINEBUF_INIT_SIZE	128
#define PORT_STR_MAX			5

// Dns Thread task. For internal usage only.
using ThreadDnsTask = WFThreadTask<DnsInput, DnsOutput>;
using thread_dns_callback_t = std::function<void (ThreadDnsTask *)>;

static constexpr struct addrinfo __ai_hints =
{
#ifdef AI_ADDRCONFIG
	.ai_flags = AI_ADDRCONFIG,
#else
	.ai_flags = 0,
#endif
	.ai_family = AF_UNSPEC,
	.ai_socktype = SOCK_STREAM,
	.ai_protocol = 0,
	.ai_addrlen = 0,
	.ai_addr = NULL,
	.ai_canonname = NULL,
	.ai_next = NULL
};

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
	struct addrinfo *res;
	struct addrinfo *cur;
	int family = AF_UNSPEC;
	bool v4 = false;
	bool v6 = false;

	if (getaddrinfo(NULL, "1", &__ai_hints, &res) == 0)
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
	struct addrinfo h;
	int errno_bak;
	FILE *fp;
	int ret;

	fp = fopen(path, "r");
	if (!fp)
		return EAI_SYSTEM;

	h = *hints;
	h.ai_flags |= AI_NUMERICSERV | AI_NUMERICHOST,
	snprintf(port_str, PORT_STR_MAX + 1, "%u", port);

	errno_bak = errno;
	while ((ret = getline(&line, &bufsize, fp)) > 0)
	{
		if (__readaddrinfo_line(line, name, port_str, &h, res) == 0)
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

// Add AI_PASSIVE to point that this addrinfo is alloced by getaddrinfo
static void __add_passive_flags(struct addrinfo *ai)
{
	while (ai)
	{
		ai->ai_flags |= AI_PASSIVE;
		ai = ai->ai_next;
	}
}

static ThreadDnsTask *__create_thread_dns_task(const std::string& host,
											   unsigned short port,
											   thread_dns_callback_t callback)
{
	auto *task = WFThreadTaskFactory<DnsInput, DnsOutput>::
						create_thread_task(WFGlobal::get_dns_queue(),
										   WFGlobal::get_dns_executor(),
										   DnsRoutine::run,
										   std::move(callback));

	task->get_input()->reset(host, port);
	return task;
}

class WFResolverTask : public WFRouterTask
{
public:
	WFResolverTask(const struct WFNSParams *params, int dns_cache_level,
				   unsigned int dns_ttl_default, unsigned int dns_ttl_min,
				   const struct EndpointParams *endpoint_params,
				   router_callback_t&& cb) :
		WFRouterTask(std::move(cb))
	{
		type_ = params->type;
		host_ = params->uri.host ? params->uri.host : "";
		port_ = params->uri.port ? atoi(params->uri.port) : 0;
		info_ = params->info;
		dns_cache_level_ = dns_cache_level;
		dns_ttl_default_ = dns_ttl_default;
		dns_ttl_min_ = dns_ttl_min;
		endpoint_params_ = *endpoint_params;
		first_addr_only_ = params->fixed_addr;
	}

private:
	virtual void dispatch();
	virtual SubTask *done();
	void thread_dns_callback(ThreadDnsTask *dns_task);
	void dns_single_callback(WFDnsTask *dns_task);
	static void dns_partial_callback(WFDnsTask *dns_task);
	void dns_parallel_callback(const ParallelWork *pwork);
	void dns_callback_internal(DnsOutput *dns_task,
							   unsigned int ttl_default,
							   unsigned int ttl_min);

private:
	TransportType type_;
	std::string host_;
	std::string info_;
	unsigned short port_;
	bool first_addr_only_;
	bool query_dns_;
	int dns_cache_level_;
	unsigned int dns_ttl_default_;
	unsigned int dns_ttl_min_;
	struct EndpointParams endpoint_params_;
};

void WFResolverTask::dispatch()
{
	if (dns_cache_level_ != DNS_CACHE_LEVEL_0)
	{
		DnsCache *dns_cache = WFGlobal::get_dns_cache();
		const DnsCache::DnsHandle *addr_handle;

		switch (dns_cache_level_)
		{
		case DNS_CACHE_LEVEL_1:
			addr_handle = dns_cache->get_confident(host_, port_);
			break;

		case DNS_CACHE_LEVEL_2:
			addr_handle = dns_cache->get_ttl(host_, port_);
			break;

		case DNS_CACHE_LEVEL_3:
			addr_handle = dns_cache->get(host_, port_);
			break;

		default:
			addr_handle = NULL;
			break;
		}

		if (addr_handle)
		{
			RouteManager *route_manager = WFGlobal::get_route_manager();
			struct addrinfo *addrinfo = addr_handle->value.addrinfo;
			struct addrinfo first;

			if (first_addr_only_ && addrinfo->ai_next)
			{
				first = *addrinfo;
				first.ai_next = NULL;
				addrinfo = &first;
			}

			if (route_manager->get(type_, addrinfo, info_, &endpoint_params_,
								   host_, this->result) < 0)
			{
				this->state = WFT_STATE_SYS_ERROR;
				this->error = errno;
			}
			else
				this->state = WFT_STATE_SUCCESS;

			dns_cache->release(addr_handle);
			query_dns_ = false;
			this->subtask_done();
			return;
		}
	}

	if (!host_.empty())
	{
		char front = host_.front();
		char back = host_.back();
		struct in6_addr addr;
		int ret;

		if (host_.find(':') != std::string::npos)
			ret = inet_pton(AF_INET6, host_.c_str(), &addr);
		else if (isdigit(back) && isdigit(front))
			ret = inet_pton(AF_INET, host_.c_str(), &addr);
		else if (front == '/')
			ret = 1;
		else
			ret = 0;

		if (ret == 1)
		{
			DnsInput dns_in(host_, port_, true); // 'true' means numeric host
			DnsOutput dns_out;

			DnsRoutine::run(&dns_in, &dns_out);
			__add_passive_flags((struct addrinfo *)dns_out.get_addrinfo());
			dns_callback_internal(&dns_out, (unsigned int)-1, (unsigned int)-1);
			query_dns_ = false;
			this->subtask_done();
			return;
		}
	}

	const char *hosts = WFGlobal::get_global_settings()->hosts_path;
	if (hosts)
	{
		struct addrinfo *ai;
		int ret = __readaddrinfo(hosts, host_.c_str(), port_, &__ai_hints, &ai);

		if (ret == 0)
		{
			DnsOutput out;
			DnsRoutine::create(&out, ret, ai);
			__add_passive_flags((struct addrinfo *)out.get_addrinfo());
			dns_callback_internal(&out, dns_ttl_default_, dns_ttl_min_);
			query_dns_ = false;
			this->subtask_done();
			return;
		}
	}

	WFDnsClient *client = WFGlobal::get_dns_client();
	if (client)
	{
		static int family = __default_family();
		WFResourcePool *respool = WFGlobal::get_dns_respool();

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
		auto&& cb = std::bind(&WFResolverTask::thread_dns_callback,
							  this,
							  std::placeholders::_1);
		ThreadDnsTask *dns_task = __create_thread_dns_task(host_, port_,
														   std::move(cb));
		series_of(this)->push_front(dns_task);
	}

	query_dns_ = true;
	this->subtask_done();
}

SubTask *WFResolverTask::done()
{
	SeriesWork *series = series_of(this);

	if (!query_dns_)
	{
		if (this->callback)
			this->callback(this);

		delete this;
	}

	return series->pop();
}

void WFResolverTask::dns_callback_internal(DnsOutput *dns_out,
										   unsigned int ttl_default,
										   unsigned int ttl_min)
{
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

		addr_handle = dns_cache->put(host_, port_, addrinfo,
									 (unsigned int)ttl_default,
									 (unsigned int)ttl_min);
		if (route_manager->get(type_, addrinfo, info_, &endpoint_params_,
							   host_, this->result) < 0)
		{
			this->state = WFT_STATE_SYS_ERROR;
			this->error = errno;
		}
		else
			this->state = WFT_STATE_SUCCESS;

		dns_cache->release(addr_handle);
	}
}

void WFResolverTask::dns_single_callback(WFDnsTask *dns_task)
{
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

	if (this->callback)
		this->callback(this);

	delete this;
}

void WFResolverTask::dns_partial_callback(WFDnsTask *dns_task)
{
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

void WFResolverTask::dns_parallel_callback(const ParallelWork *pwork)
{
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

	if (this->callback)
		this->callback(this);

	delete this;
}

void WFResolverTask::thread_dns_callback(ThreadDnsTask *dns_task)
{
	if (dns_task->get_state() == WFT_STATE_SUCCESS)
	{
		DnsOutput *out = dns_task->get_output();
		__add_passive_flags((struct addrinfo *)out->get_addrinfo());
		dns_callback_internal(out, dns_ttl_default_, dns_ttl_min_);
	}
	else
	{
		this->state = dns_task->get_state();
		this->error = dns_task->get_error();
	}

	if (this->callback)
		this->callback(this);

	delete this;
}

WFRouterTask *
WFDnsResolver::create(const struct WFNSParams *params, int dns_cache_level,
					  unsigned int dns_ttl_default, unsigned int dns_ttl_min,
					  const struct EndpointParams *endpoint_params,
					  router_callback_t&& callback)
{
	return new WFResolverTask(params, dns_cache_level, dns_ttl_default,
							  dns_ttl_min, endpoint_params,
							  std::move(callback));
}

WFRouterTask *WFDnsResolver::create_router_task(const struct WFNSParams *params,
												router_callback_t callback)
{
	const struct WFGlobalSettings *settings = WFGlobal::get_global_settings();
	unsigned int dns_ttl_default = settings->dns_ttl_default;
	unsigned int dns_ttl_min = settings->dns_ttl_min;
	const struct EndpointParams *endpoint_params = &settings->endpoint_params;
	int dns_cache_level = params->retry_times == 0 ? DNS_CACHE_LEVEL_2 :
													 DNS_CACHE_LEVEL_1;
	return create(params, dns_cache_level, dns_ttl_default, dns_ttl_min,
				  endpoint_params, std::move(callback));
}


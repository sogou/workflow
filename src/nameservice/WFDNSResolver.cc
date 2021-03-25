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

  Authors: Wu Jiaxu (wujiaxu@sogou-inc.com)
           Xie Han (xiehan@sogou-inc.com)
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <ctype.h>
#include <utility>
#include <string>
#include "DNSRoutine.h"
#include "EndpointParams.h"
#include "RouteManager.h"
#include "WFGlobal.h"
#include "WFTaskError.h"
#include "WFTaskFactory.h"
#include "WFNameService.h"
#include "WFDNSResolver.h"

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

class WFResolverTask : public WFRouterTask
{
public:
	WFResolverTask(const struct WFNSParams *params, int dns_cache_level,
				   unsigned int dns_ttl_default, unsigned int dns_ttl_min,
				   const struct EndpointParams *endpoint_params,
				   router_callback_t&& cb) :
		WFRouterTask(std::move(cb)),
		type_(params->type),
		host_(params->uri.host ? params->uri.host : ""),
		port_(params->uri.port ? atoi(params->uri.port) : 0),
		info_(params->info),
		dns_cache_level_(dns_cache_level),
		dns_ttl_default_(dns_ttl_default),
		dns_ttl_min_(dns_ttl_min),
		endpoint_params_(*endpoint_params),
		first_addr_only_(params->fixed_addr)
	{
	}

private:
	virtual void dispatch();
	virtual SubTask *done();
	void dns_callback(WFDNSTask *dns_task);
	void dns_callback_internal(DNSOutput *dns_task,
							   unsigned int ttl_default,
							   unsigned int ttl_min);

private:
	TransportType type_;
	std::string host_;
	unsigned short port_;
	std::string info_;
	int dns_cache_level_;
	unsigned int dns_ttl_default_;
	unsigned int dns_ttl_min_;
	struct EndpointParams endpoint_params_;
	bool first_addr_only_;
	bool insert_dns_;
};

void WFResolverTask::dispatch()
{
	insert_dns_ = true;
	if (dns_cache_level_ != DNS_CACHE_LEVEL_0)
	{
		auto *dns_cache = WFGlobal::get_dns_cache();
		const DNSCache::DNSHandle *addr_handle = NULL;

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
			break;
		}

		if (addr_handle)
		{
			auto *route_manager = WFGlobal::get_route_manager();
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

			insert_dns_ = false;
			dns_cache->release(addr_handle);
		}
	}

	if (insert_dns_ && !host_.empty())
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
			DNSInput dns_in;
			DNSOutput dns_out;

			dns_in.reset(host_, port_);
			DNSRoutine::run(&dns_in, &dns_out);
			dns_callback_internal(&dns_out, (unsigned int)-1, (unsigned int)-1);
			insert_dns_ = false;
		}
	}

	if (insert_dns_)
	{
		auto&& cb = std::bind(&WFResolverTask::dns_callback,
							  this,
							  std::placeholders::_1);
		WFDNSTask *dns_task = WFTaskFactory::create_dns_task(host_, port_,
															 std::move(cb));
		series_of(this)->push_front(dns_task);
	}

	this->subtask_done();
}

SubTask *WFResolverTask::done()
{
	SeriesWork *series = series_of(this);

	if (!insert_dns_)
	{
		if (this->callback)
			this->callback(this);

		delete this;
	}

	return series->pop();
}

void WFResolverTask::dns_callback_internal(DNSOutput *dns_out,
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
		auto *route_manager = WFGlobal::get_route_manager();
		auto *dns_cache = WFGlobal::get_dns_cache();
		struct addrinfo *addrinfo = dns_out->move_addrinfo();
		const DNSCache::DNSHandle *addr_handle;

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

void WFResolverTask::dns_callback(WFDNSTask *dns_task)
{
	if (dns_task->get_state() == WFT_STATE_SUCCESS)
		dns_callback_internal(dns_task->get_output(), dns_ttl_default_, dns_ttl_min_);
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
WFDNSResolver::create(const struct WFNSParams *params, int dns_cache_level,
					  unsigned int dns_ttl_default, unsigned int dns_ttl_min,
					  const struct EndpointParams *endpoint_params,
					  router_callback_t&& callback)
{
	return new WFResolverTask(params, dns_cache_level,
							  dns_ttl_default, dns_ttl_min,
							  endpoint_params, std::move(callback));
}

WFRouterTask *WFDNSResolver::create_router_task(const struct WFNSParams *params,
												router_callback_t callback)
{
	const auto *settings = WFGlobal::get_global_settings();
	unsigned int dns_ttl_default = settings->dns_ttl_default;
	unsigned int dns_ttl_min = settings->dns_ttl_min;
	const struct EndpointParams *endpoint_params = &settings->endpoint_params;
	int dns_cache_level = params->retry_times == 0 ? DNS_CACHE_LEVEL_2 :
													 DNS_CACHE_LEVEL_1;
	return create(params, dns_cache_level, dns_ttl_default, dns_ttl_min,
				  endpoint_params, std::move(callback));
}


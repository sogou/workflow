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

  Authors: Li Yingxin (liyingxin@sogou-inc.com)
           Xie Han (xiehan@sogou-inc.com)
*/

#include <stdint.h>
#include <vector>
#include <chrono>
#include "URIParser.h"
#include "WFTaskError.h"
#include "StringUtil.h"
#include "WFGlobal.h"
#include "WFNameService.h"
#include "WFDnsResolver.h"
#include "WFServiceGovernance.h"

#define GET_CURRENT_SECOND  std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count()

#define DNS_CACHE_LEVEL_1		1
#define DNS_CACHE_LEVEL_2		2

PolicyAddrParams::PolicyAddrParams()
{
	const struct AddressParams *params = &ADDRESS_PARAMS_DEFAULT;
	this->endpoint_params = params->endpoint_params;
	this->dns_ttl_default = params->dns_ttl_default;
	this->dns_ttl_min = params->dns_ttl_min;
	this->max_fails = params->max_fails;
}

PolicyAddrParams::PolicyAddrParams(const struct AddressParams *params) :
	endpoint_params(params->endpoint_params)
{
	this->dns_ttl_default = params->dns_ttl_default;
	this->dns_ttl_min = params->dns_ttl_min;
	this->max_fails = params->max_fails;
}

class WFSelectorFailTask : public WFRouterTask
{
public:
	WFSelectorFailTask(router_callback_t&& cb) :
		WFRouterTask(std::move(cb))
	{
	}

	virtual void dispatch()
	{
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_UPSTREAM_UNAVAILABLE;

		return this->subtask_done();
	}
};

static void copy_host_port(ParsedURI& uri, const EndpointAddress *addr)
{
	if (!addr->host.empty())
	{
		free(uri.host);
		uri.host = strdup(addr->host.c_str());
	}

	if (!addr->port.empty())
	{
		free(uri.port);
		uri.port = strdup(addr->port.c_str());
	}
}

EndpointAddress::EndpointAddress(const std::string& address,
								 PolicyAddrParams *address_params)
{
	std::vector<std::string> arr = StringUtil::split(address, ':');

	this->params = address_params;
	if (this->params->max_fails == 0)
		this->params->max_fails = 1;

	this->address = address;
	this->fail_count = 0;
	this->ref = 1;
	this->entry.list.next = NULL;
	this->entry.ptr = this;

	if (arr.size() == 0)
		this->host = "";
	else
		this->host = arr[0];

	if (arr.size() <= 1)
		this->port = "";
	else
		this->port = arr[1];
}

WFRouterTask *WFServiceGovernance::create_router_task(const struct WFNSParams *params,
													  router_callback_t callback)
{
	WFNSTracing *tracing = params->tracing;
	EndpointAddress *addr;
	WFRouterTask *task;

	if (this->select(params->uri, tracing, &addr))
	{
		WFDnsResolver *resolver = WFGlobal::get_dns_resolver();
		unsigned int dns_ttl_default = addr->params->dns_ttl_default;
		unsigned int dns_ttl_min = addr->params->dns_ttl_min;
		const struct EndpointParams *endpoint_params = &addr->params->endpoint_params;
		int dns_cache_level = params->retry_times == 0 ? DNS_CACHE_LEVEL_2 :
														 DNS_CACHE_LEVEL_1;

		copy_host_port(params->uri, addr);
		task = resolver->create(params, dns_cache_level, dns_ttl_default, dns_ttl_min,
								endpoint_params, std::move(callback));

		struct TracingData *tracing_data = (struct TracingData *)tracing->data;
		if (!tracing_data)
		{
			tracing_data = new TracingData;
			tracing_data->sg = this;
			tracing->data = tracing_data;
			tracing->deleter = WFServiceGovernance::tracing_deleter;
		}

		tracing_data->history.push_back(addr);
	}
	else
		task = new WFSelectorFailTask(std::move(callback));

	return task;
}

void WFServiceGovernance::tracing_deleter(void *data)
{
	struct TracingData *tracing_data = (struct TracingData *)data;

	for (EndpointAddress *addr : tracing_data->history)
	{
		if (--addr->ref == 0)
		{
			pthread_rwlock_wrlock(&tracing_data->sg->rwlock);
			tracing_data->sg->pre_delete_server(addr);
			pthread_rwlock_unlock(&tracing_data->sg->rwlock);
			delete addr;
		}
	}

	delete tracing_data;
}

bool WFServiceGovernance::in_select_history(WFNSTracing *tracing,
											EndpointAddress *addr)
{
	struct TracingData *tracing_data = (struct TracingData *)tracing->data;

	if (!tracing_data)
		return false;

	for (EndpointAddress *server : tracing_data->history)
	{
		if (server == addr)
			return true;
	}

	return false;
}

void WFServiceGovernance::recover_server_from_breaker(EndpointAddress *addr)
{
	addr->fail_count = 0;
	pthread_mutex_lock(&this->breaker_lock);
	if (addr->entry.list.next)
	{
		list_del(&addr->entry.list);
		addr->entry.list.next = NULL;
		this->recover_one_server(addr);
		this->server_list_change(addr, RECOVER_SERVER);
	}
	pthread_mutex_unlock(&this->breaker_lock);
}

void WFServiceGovernance::fuse_server_to_breaker(EndpointAddress *addr)
{
	pthread_mutex_lock(&this->breaker_lock);
	if (!addr->entry.list.next)
	{
		addr->broken_timeout = GET_CURRENT_SECOND + this->mttr_second;
		list_add_tail(&addr->entry.list, &this->breaker_list);
		this->fuse_one_server(addr);
		this->server_list_change(addr, FUSE_SERVER);
	}
	pthread_mutex_unlock(&this->breaker_lock);
}

void WFServiceGovernance::pre_delete_server(EndpointAddress *addr)
{
	pthread_mutex_lock(&this->breaker_lock);
	if (addr->entry.list.next)
	{
		list_del(&addr->entry.list);
		addr->entry.list.next = NULL;
	}
	else
		this->fuse_one_server(addr);
	pthread_mutex_unlock(&this->breaker_lock);
}

void WFServiceGovernance::success(RouteManager::RouteResult *result,
								  WFNSTracing *tracing,
								  CommTarget *target)
{
	struct TracingData *tracing_data = (struct TracingData *)tracing->data;
	auto *v = &tracing_data->history;
	EndpointAddress *server = (*v)[v->size() - 1];

	pthread_rwlock_wrlock(&this->rwlock);
	this->recover_server_from_breaker(server);
	pthread_rwlock_unlock(&this->rwlock);

	this->WFNSPolicy::success(result, tracing, target);
}

void WFServiceGovernance::failed(RouteManager::RouteResult *result,
								 WFNSTracing *tracing,
								 CommTarget *target)
{
	struct TracingData *tracing_data = (struct TracingData *)tracing->data;
	auto *v = &tracing_data->history;
	EndpointAddress *server = (*v)[v->size() - 1];

	pthread_rwlock_wrlock(&this->rwlock);
	if (++server->fail_count == server->params->max_fails)
		this->fuse_server_to_breaker(server);
	pthread_rwlock_unlock(&this->rwlock);

	this->WFNSPolicy::failed(result, tracing, target);
}

void WFServiceGovernance::check_breaker_locked(int64_t cur_time)
{
	struct list_head *pos, *tmp;
	struct EndpointAddress::address_entry *entry;
	EndpointAddress *addr;

	list_for_each_safe(pos, tmp, &this->breaker_list)
	{
		entry = list_entry(pos, struct EndpointAddress::address_entry, list);
		addr = entry->ptr;

		if (cur_time >= addr->broken_timeout)
		{
			addr->fail_count = addr->params->max_fails - 1;
			this->recover_one_server(addr);
			this->server_list_change(addr, RECOVER_SERVER);
			list_del(pos);
			pos->next = NULL;
		}
		else
			break;
	}
}

void WFServiceGovernance::check_breaker()
{
	pthread_mutex_lock(&this->breaker_lock);
	if (!list_empty(&this->breaker_list))
		this->check_breaker_locked(GET_CURRENT_SECOND);
	pthread_mutex_unlock(&this->breaker_lock);
}

void WFServiceGovernance::try_clear_breaker()
{
	pthread_mutex_lock(&this->breaker_lock);
	if (!list_empty(&this->breaker_list))
	{
		struct list_head *pos = this->breaker_list.next;
		struct EndpointAddress::address_entry *entry;
		entry = list_entry(pos, struct EndpointAddress::address_entry, list);
		if (GET_CURRENT_SECOND >= entry->ptr->broken_timeout)
			this->check_breaker_locked(INT64_MAX);
	}
	pthread_mutex_unlock(&this->breaker_lock);
}

EndpointAddress *WFServiceGovernance::first_strategy(const ParsedURI& uri,
													 WFNSTracing *tracing)
{
	unsigned int idx = rand() % this->servers.size();
	return this->servers[idx];
}

EndpointAddress *WFServiceGovernance::another_strategy(const ParsedURI& uri,
													   WFNSTracing *tracing)
{
	return this->first_strategy(uri, tracing);
}

bool WFServiceGovernance::select(const ParsedURI& uri, WFNSTracing *tracing,
								 EndpointAddress **addr)
{
	pthread_rwlock_rdlock(&this->rwlock);
	unsigned int n = (unsigned int)this->servers.size();

	if (n == 0)
	{
		pthread_rwlock_unlock(&this->rwlock);
		return false;
	}

	this->check_breaker();
	if (this->nalives == 0)
	{
		pthread_rwlock_unlock(&this->rwlock);
		return false;
	}

	// select_addr == NULL will only happened in consistent_hash
	EndpointAddress *select_addr = this->first_strategy(uri, tracing);

	if (!select_addr ||
		select_addr->fail_count >= select_addr->params->max_fails)
	{
		if (this->try_another)
			select_addr = this->another_strategy(uri, tracing);
	}

	if (select_addr)
	{
		*addr = select_addr;
		++select_addr->ref;
	}

	pthread_rwlock_unlock(&this->rwlock);
	return !!select_addr;
}

void WFServiceGovernance::add_server_locked(EndpointAddress *addr)
{
	this->server_map[addr->address].push_back(addr);
	this->servers.push_back(addr);
	this->recover_one_server(addr);
	this->server_list_change(addr, ADD_SERVER);
}

int WFServiceGovernance::remove_server_locked(const std::string& address)
{
	const auto map_it = this->server_map.find(address);
	size_t n = this->servers.size();
	size_t new_n = 0;
	int ret = 0;

	for (size_t i = 0; i < n; i++)
	{
		if (this->servers[i]->address != address)
			this->servers[new_n++] = this->servers[i];
	}

	this->servers.resize(new_n);

	if (map_it != this->server_map.cend())
	{
		for (EndpointAddress *addr : map_it->second)
		{
			this->server_list_change(addr, REMOVE_SERVER);
			if (--addr->ref == 0)
			{
				this->pre_delete_server(addr);
				delete addr;
			}

			ret++;
		}

		this->server_map.erase(map_it);
	}

	return ret;
}

void WFServiceGovernance::add_server(const std::string& address,
									 const AddressParams *params)
{
	EndpointAddress *addr = new EndpointAddress(address,
									new PolicyAddrParams(params));

	pthread_rwlock_wrlock(&this->rwlock);
	this->add_server_locked(addr);
	pthread_rwlock_unlock(&this->rwlock);
}

int WFServiceGovernance::remove_server(const std::string& address)
{
	int ret;
	pthread_rwlock_wrlock(&this->rwlock);
	ret = this->remove_server_locked(address);
	pthread_rwlock_unlock(&this->rwlock);
	return ret;
}

int WFServiceGovernance::replace_server(const std::string& address,
										const AddressParams *params)
{
	int ret;
	EndpointAddress *addr = new EndpointAddress(address,
									new PolicyAddrParams(params));

	pthread_rwlock_wrlock(&this->rwlock);
	ret = this->remove_server_locked(address);
	this->add_server_locked(addr);
	pthread_rwlock_unlock(&this->rwlock);
	return ret;
}

void WFServiceGovernance::enable_server(const std::string& address)
{
	pthread_rwlock_wrlock(&this->rwlock);
	const auto map_it = this->server_map.find(address);
	if (map_it != this->server_map.cend())
	{
		for (EndpointAddress *addr : map_it->second)
			this->recover_server_from_breaker(addr);
	}
	pthread_rwlock_unlock(&this->rwlock);
}

void WFServiceGovernance::disable_server(const std::string& address)
{
	pthread_rwlock_wrlock(&this->rwlock);
	const auto map_it = this->server_map.find(address);
	if (map_it != this->server_map.cend())
	{
		for (EndpointAddress *addr : map_it->second)
		{
			addr->fail_count = addr->params->max_fails;
			this->fuse_server_to_breaker(addr);
		}
	}
	pthread_rwlock_unlock(&this->rwlock);
}

void WFServiceGovernance::get_current_address(std::vector<std::string>& addr_list)
{
	pthread_rwlock_rdlock(&this->rwlock);

	for (const EndpointAddress *server : this->servers)
		addr_list.push_back(server->address);

	pthread_rwlock_unlock(&this->rwlock);
}


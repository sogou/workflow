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

  Authors: Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

#include <algorithm>
#include "StringUtil.h"
#include "UpstreamPolicies.h"
#include "WFDNSResolver.h"

#define DNS_CACHE_LEVEL_1		1
#define DNS_CACHE_LEVEL_2		2

class WFSelectorFailTask : public WFRouterTask
{
public:
	WFSelectorFailTask(router_callback_t&& cb)
		: WFRouterTask(std::move(cb))
	{
	}

	virtual void dispatch()
	{
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_UPSTREAM_UNAVAILABLE;

		return this->subtask_done();
	}
};

static bool copy_host_port(ParsedURI& uri, const EndpointAddress *addr)
{
	char *host = NULL;
	char *port = NULL;

	if (!addr->host.empty())
	{
		host = strdup(addr->host.c_str());
		if (!host)
			return false;
	}

	if (addr->port_value > 0)
	{
		port = strdup(addr->port.c_str());
		if (!port)
		{
			free(host);
			return false;
		}
		free(uri.port);
		uri.port = port;
	}

	free(uri.host);
	uri.host = host;
	return true;
}

EndpointAddress::EndpointAddress(const std::string& address,
								 const struct AddressParams *address_params)
{
	std::vector<std::string> arr = StringUtil::split(address, ':');
	this->params = *address_params;
	this->address = address;

	static std::hash<std::string> std_hash;
	for (int i = 0; i < VIRTUAL_GROUP_SIZE; i++)
		this->consistent_hash[i] = std_hash(address + "|v" + std::to_string(i));

	if (this->params.weight == 0)
		this->params.weight = 1;

	if (this->params.max_fails == 0)
		this->params.max_fails = 1;

	if (this->params.group_id < 0)
		this->params.group_id = -1;

	if (arr.size() == 0)
		this->host = "";
	else
		this->host = arr[0];

	if (arr.size() <= 1)
	{
		this->port = "";
		this->port_value = 0;
	}
	else
	{
		this->port = arr[1];
		this->port_value = atoi(arr[1].c_str());
	}
}

WFRouterTask *UPSPolicy::create_router_task(const struct WFNSParams *params,
											router_callback_t callback)
{
	EndpointAddress *addr;
	WFRouterTask *task;

	if (this->select(params->uri, &addr) && copy_host_port(params->uri, addr))
	{
		const auto *settings = WFGlobal::get_global_settings();
		unsigned int dns_ttl_default = settings->dns_ttl_default;
		unsigned int dns_ttl_min = settings->dns_ttl_min;
		const struct EndpointParams *endpoint_params = &settings->endpoint_params;
		int dns_cache_level = params->retry_times == 0 ? DNS_CACHE_LEVEL_2 :
														 DNS_CACHE_LEVEL_1;
		task = this->create(params, dns_cache_level, dns_ttl_default, dns_ttl_min,
							endpoint_params, std::move(callback));
		task->set_cookie(addr);
	}
	else
		task = new WFSelectorFailTask(std::move(callback));

	return task;
}

inline void UPSPolicy::recover_server_from_breaker(EndpointAddress *addr)
{
	addr->fail_count = 0;
	pthread_mutex_lock(&this->breaker_lock);
	if (addr->list.next)
	{
		list_del(&addr->list);
		addr->list.next = NULL;
		this->recover_one_server(addr);
		//this->server_list_change();
	}
	pthread_mutex_unlock(&this->breaker_lock);
}

inline void UPSPolicy::fuse_server_to_breaker(EndpointAddress *addr)
{
	pthread_mutex_lock(&this->breaker_lock);
	if (!addr->list.next)
	{
		addr->broken_timeout = GET_CURRENT_SECOND + MTTR_SECOND;
		list_add_tail(&addr->list, &this->breaker_list);
		this->fuse_one_server(addr);
		//this->server_list_change();
	}
	pthread_mutex_unlock(&this->breaker_lock);
}

void UPSPolicy::success(RouteManager::RouteResult *result, void *cookie,
					 		   CommTarget *target)
{
	pthread_rwlock_rdlock(&this->rwlock);
	this->recover_server_from_breaker((EndpointAddress *)cookie);
	pthread_rwlock_unlock(&this->rwlock);

	WFDNSResolver::success(result, NULL, target);
}

void UPSPolicy::failed(RouteManager::RouteResult *result, void *cookie,
							  CommTarget *target)
{
	EndpointAddress *server = (EndpointAddress *)cookie;

	pthread_rwlock_rdlock(&this->rwlock);
	size_t fail_count = ++server->fail_count;
	if (fail_count == server->params.max_fails)
		this->fuse_server_to_breaker(server);

	pthread_rwlock_unlock(&this->rwlock);

	WFDNSResolver::failed(result, NULL, target);
}

void UPSPolicy::check_breaker()
{
	pthread_mutex_lock(&this->breaker_lock);
	if (!list_empty(&this->breaker_list))
	{
		int64_t cur_time = GET_CURRENT_SECOND;
		struct list_head *pos, *tmp;
		EndpointAddress *addr;

		list_for_each_safe(pos, tmp, &this->breaker_list)
		{
			addr = list_entry(pos, EndpointAddress, list);
			if (cur_time >= addr->broken_timeout)
			{
				if (addr->fail_count >= addr->params.max_fails)
				{
					addr->fail_count = addr->params.max_fails - 1;
					this->recover_one_server(addr);
				}
				list_del(pos);
				addr->list.next = NULL;
			}
		}
	}
	pthread_mutex_unlock(&this->breaker_lock);
	
	//this->server_list_change();
}

const EndpointAddress *UPSPolicy::first_stradegy(const ParsedURI& uri)
{
	unsigned int idx = rand() % this->servers.size();
	return this->servers[idx];
}

const EndpointAddress *UPSPolicy::another_stradegy(const ParsedURI& uri)
{
	return this->first_stradegy(uri);
}

bool UPSPolicy::select(const ParsedURI& uri, EndpointAddress **addr)
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
	const EndpointAddress *select_addr = this->first_stradegy(uri);

	if (!select_addr || select_addr->fail_count >= select_addr->params.max_fails)
	{
		if (this->try_another)
			select_addr = this->another_stradegy(uri);
	}

	pthread_rwlock_unlock(&this->rwlock);

	if (select_addr)
	{
		*addr = (EndpointAddress *)select_addr;
		return true;
	}

	return false;
}

void UPSPolicy::add_server_locked(EndpointAddress *addr)
{
	this->addresses.push_back(addr);
	this->server_map[addr->address].push_back(addr);
	this->servers.push_back(addr);
	this->recover_one_server(addr);
}

int UPSPolicy::remove_server_locked(const std::string& address)
{
	const auto map_it = this->server_map.find(address);
	if (map_it != this->server_map.cend())
	{
		for (EndpointAddress *addr : map_it->second)
		{
			// or not: it has already been -- in nalives
			if (addr->fail_count < addr->params.max_fails)
				this->fuse_one_server(addr);
		}

		this->server_map.erase(map_it);
	}

	size_t n = this->servers.size();
	size_t new_n = 0;

	for (size_t i = 0; i < n; i++)
	{
		if (this->servers[i]->address != address)
		{
			if (new_n != i)
				this->servers[new_n++] = this->servers[i];
			else
				new_n++;
		}
	}

	int ret = 0;
	if (new_n < n)
	{
		this->servers.resize(new_n);
		ret = n - new_n;
	}

	return ret;
}

void UPSPolicy::add_server(const std::string& address,
						   const AddressParams *address_params)
{
	EndpointAddress *addr = new EndpointAddress(address, address_params);

	pthread_rwlock_wrlock(&this->rwlock);
	this->add_server_locked(addr);
	pthread_rwlock_unlock(&this->rwlock);
}

int UPSPolicy::remove_server(const std::string& address)
{
	int ret;
	pthread_rwlock_wrlock(&this->rwlock);
	ret = this->remove_server_locked(address);
	pthread_rwlock_unlock(&this->rwlock);
	return ret;
}

int UPSPolicy::replace_server(const std::string& address,
							  const AddressParams *address_params)
{
	int ret;
	EndpointAddress *addr = new EndpointAddress(address, address_params);

	pthread_rwlock_wrlock(&this->rwlock);
	this->add_server_locked(addr);
	ret = this->remove_server_locked(address);
	pthread_rwlock_unlock(&this->rwlock);
	return ret;
}

void UPSPolicy::enable_server(const std::string& address)
{
	pthread_rwlock_rdlock(&this->rwlock);
	const auto map_it = this->server_map.find(address);
	if (map_it != this->server_map.cend())
	{
		for (EndpointAddress *addr : map_it->second)
			this->recover_server_from_breaker(addr);
	}
	pthread_rwlock_unlock(&this->rwlock);
}

void UPSPolicy::disable_server(const std::string& address)
{
	pthread_rwlock_rdlock(&this->rwlock);
	const auto map_it = this->server_map.find(address);
	if (map_it != this->server_map.cend())
	{
		for (EndpointAddress *addr : map_it->second)
		{
			addr->fail_count = addr->params.max_fails;
			this->fuse_server_to_breaker(addr);
		}
	}
	pthread_rwlock_unlock(&this->rwlock);
}

void UPSPolicy::get_main_address(std::vector<std::string>& addr_list)
{
	pthread_rwlock_rdlock(&this->rwlock);

	for (const EndpointAddress *server : this->servers)
		addr_list.push_back(server->address);

	pthread_rwlock_unlock(&this->rwlock);
}

UPSGroupPolicy::UPSGroupPolicy()
{
	this->group_map.rb_node = NULL;
	this->default_group = new EndpointGroup(-1, this);
	rb_link_node(&this->default_group->rb, NULL, &this->group_map.rb_node);
	rb_insert_color(&this->default_group->rb, &this->group_map);
}

UPSGroupPolicy::~UPSGroupPolicy()
{
    EndpointGroup *group;

    while (this->group_map.rb_node)
    {    
        group = rb_entry(this->group_map.rb_node, EndpointGroup, rb);
        rb_erase(this->group_map.rb_node, &this->group_map);
        delete group;
    }
}

bool UPSGroupPolicy::select(const ParsedURI& uri, EndpointAddress **addr)
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
	const EndpointAddress *select_addr = this->first_stradegy(uri);

	if (!select_addr || select_addr->fail_count >= select_addr->params.max_fails)
	{
		if (select_addr)
			select_addr = select_addr->group->get_one();

		if (!select_addr && this->try_another)
			select_addr = this->another_stradegy(uri);
	}

	if (!select_addr)
		this->default_group->get_one_backup();
	
	pthread_rwlock_unlock(&this->rwlock);

	if (select_addr)
	{
		*addr = (EndpointAddress *)select_addr;
		return true;
	}

	return false;
}

const EndpointAddress *EndpointGroup::get_one()
{
	if (this->nalives == 0)
		return NULL;

	const EndpointAddress *addr = NULL;
	pthread_mutex_lock(&this->mutex);

	std::random_shuffle(this->mains.begin(), this->mains.end());
	for (size_t i = 0; i < this->mains.size(); i++)
	{
		if (this->mains[i]->fail_count < this->mains[i]->params.max_fails)
		{
			addr = this->mains[i];
			break;
		}
	}

	if (!addr)
	{
		std::random_shuffle(this->backups.begin(), this->backups.end());
		for (size_t i = 0; i < this->backups.size(); i++)
		{
			if (this->backups[i]->fail_count < this->backups[i]->params.max_fails)
			{
				addr = this->backups[i];
				break;
			}
		}
	}

	pthread_mutex_unlock(&this->mutex);
	return addr;
}

const EndpointAddress *EndpointGroup::get_one_backup()
{
	if (this->nalives == 0)
		return NULL;

	const EndpointAddress *addr = NULL;
	pthread_mutex_lock(&this->mutex);

	std::random_shuffle(this->backups.begin(), this->backups.end());
	for (size_t i = 0; i < this->backups.size(); i++)
	{
		if (this->backups[i]->fail_count < this->backups[i]->params.max_fails)
		{
			addr = this->backups[i];
			break;
		}
	}

	pthread_mutex_unlock(&this->mutex);
	return addr;
}

void UPSGroupPolicy::add_server_locked(EndpointAddress *addr)
{
	int group_id = addr->params.group_id;
	rb_node **p = &this->group_map.rb_node;
	rb_node *parent = NULL;
	EndpointGroup *group;

	this->addresses.push_back(addr);
	this->server_map[addr->address].push_back(addr);

	if (addr->params.server_type == 0)
		this->servers.push_back(addr);

	while (*p)
	{
		parent = *p;
		group = rb_entry(*p, EndpointGroup, rb);

		if (group_id < group->id)
			p = &(*p)->rb_left;
		else if (group_id > group->id)
			p = &(*p)->rb_right;
		else
			break;
	}

	if (*p == NULL)
	{
		group = new EndpointGroup(group_id, this);
		rb_link_node(&group->rb, parent, p);
		rb_insert_color(&group->rb, &this->group_map);
	}

	pthread_mutex_lock(&group->mutex);
	addr->group = group;
	this->recover_one_server(addr);
	if (addr->params.server_type == 0)
	{
		group->mains.push_back(addr);
		group->weight += addr->params.weight;
	}
	else
		group->backups.push_back(addr);
	pthread_mutex_unlock(&group->mutex);

	return;
}

int UPSGroupPolicy::remove_server_locked(const std::string& address)
{
	const auto map_it = this->server_map.find(address);

	if (map_it != this->server_map.cend())
	{
		for (EndpointAddress *addr : map_it->second)
		{
			EndpointGroup *group = addr->group;
			std::vector<EndpointAddress *> *vec;

			if (addr->params.server_type == 0)
				vec = &group->mains;
			else
				vec = &group->backups;

			//std::lock_guard<std::mutex> lock(group->mutex);
			pthread_mutex_lock(&group->mutex);
			if (addr->fail_count < addr->params.max_fails)
				this->fuse_one_server(addr);

			if (addr->params.server_type == 0)
				group->weight -= addr->params.weight;

			for (auto it = vec->begin(); it != vec->end(); ++it)
			{
				if (*it == addr)
				{
					vec->erase(it);
					break;
				}
			}
			pthread_mutex_unlock(&group->mutex);
		}

		this->server_map.erase(map_it);
	}

	size_t n = this->servers.size();
	size_t new_n = 0;

	for (size_t i = 0; i < n; i++)
	{
		if (this->servers[i]->address != address)
		{
			if (new_n != i)
				this->servers[new_n++] = this->servers[i];
			else
				new_n++;
		}
	}

	int ret = 0;
	if (new_n < n)
	{
		this->servers.resize(new_n);
		ret = n - new_n;
	}

	return ret;
}

const EndpointAddress *UPSGroupPolicy::consistent_hash_with_group(unsigned int hash) const
{
	const EndpointAddress *addr = NULL;
	unsigned int min_dis = (unsigned int)-1;

	for (const EndpointAddress *server : this->servers)
	{
		if (this->is_alive_or_group_alive(server))
		{
			for (int i = 0; i < VIRTUAL_GROUP_SIZE; i++)
			{
				unsigned int dis = std::min<unsigned int>
								   (hash - server->consistent_hash[i],
								   server->consistent_hash[i] - hash);

				if (dis < min_dis)
				{
					min_dis = dis;
					addr = server;
				}
			}
		}
	}

	return this->check_and_get(addr);
}

void UPSWeightedRandomPolicy::add_server_locked(EndpointAddress *addr)
{
	UPSGroupPolicy::add_server_locked(addr);
	if (addr->params.server_type == 0)
		this->total_weight += addr->params.weight;
	return;
}

int UPSWeightedRandomPolicy::remove_server_locked(const std::string& address)
{
	const auto map_it = this->server_map.find(address);

	if (map_it != this->server_map.cend())
	{
		for (EndpointAddress *addr : map_it->second)
		{
			if (addr->params.server_type == 0)
				this->total_weight -= addr->params.weight;
		}
	}

	return UPSGroupPolicy::remove_server_locked(address);
}

const EndpointAddress *UPSWeightedRandomPolicy::first_stradegy(const ParsedURI& uri)
{
	int x = 0;
	int s = 0;
	size_t idx;
	int temp_weight = this->total_weight;

	if (temp_weight > 0)
		x = rand() % temp_weight;

	for (idx = 0; idx < this->servers.size(); idx++)
	{
		s += this->servers[idx]->params.weight;
		if (s > x)
			break;
	}
	if (idx == this->servers.size())
		idx--;

	return this->servers[idx];
}

const EndpointAddress *UPSWeightedRandomPolicy::another_stradegy(const ParsedURI& uri)
{
	int temp_weight = this->available_weight;
	if (temp_weight == 0)
		return NULL;

	const EndpointAddress *addr = NULL;
	int x = rand() % temp_weight;
	int s = 0;

	for (const EndpointAddress *server : this->servers)
	{
		if (this->is_alive_or_group_alive(server))
		{
			addr = server;
			s += server->params.weight;
			if (s > x)
				break;
		}
	}
	return this->check_and_get(addr);
}

void UPSWeightedRandomPolicy::recover_one_server(const EndpointAddress *addr)
{
	this->nalives++;
	if (addr->group->nalives++ == 0 && addr->group->id > 0)
		this->available_weight += addr->group->weight;

	if (addr->params.group_id < 0 && addr->params.server_type == 0)
		this->available_weight += addr->params.weight;
}

void UPSWeightedRandomPolicy::fuse_one_server(const EndpointAddress *addr)
{
	this->nalives--;
	if (--addr->group->nalives == 0 && addr->group->id > 0)
		this->available_weight -= addr->group->weight;

	if (addr->params.group_id < 0 && addr->params.server_type == 0)
		this->available_weight -= addr->params.weight;
}

const EndpointAddress *UPSConsistentHashPolicy::first_stradegy(const ParsedURI& uri)
{
	unsigned int hash_value;

	if (this->consistent_hash)
		hash_value = this->consistent_hash(uri.path ? uri.path : "",
										   uri.query ? uri.query : "",
										   uri.fragment ? uri.fragment : "");
	else
		hash_value = this->default_consistent_hash(uri.path ? uri.path : "",
												   uri.query ? uri.query : "",
												   uri.fragment ? uri.fragment : "");
	return this->consistent_hash_with_group(hash_value);
}

const EndpointAddress *UPSManualPolicy::first_stradegy(const ParsedURI& uri)
{
	unsigned int idx = this->manual_select(uri.path ? uri.path : "",
										   uri.query ? uri.query : "",
										   uri.fragment ? uri.fragment : ""); 

	if (idx >= this->servers.size())
		idx %= this->servers.size();

	return this->servers[idx];
}

const EndpointAddress *UPSManualPolicy::another_stradegy(const ParsedURI& uri)
{
	unsigned int hash_value;

	if (this->try_another_select)
		hash_value = this->try_another_select(uri.path ? uri.path : "",
											  uri.query ? uri.query : "",
											  uri.fragment ? uri.fragment : "");
	else
		hash_value = UPSConsistentHashPolicy::default_consistent_hash(uri.path ? uri.path : "",
																   uri.query ? uri.query : "",
																   uri.fragment ? uri.fragment : "");
	return this->consistent_hash_with_group(hash_value);
}


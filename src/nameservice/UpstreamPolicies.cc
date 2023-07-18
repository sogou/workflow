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
           Wang Zhulei (wangzhulei@sogou-inc.com)
*/

#include <stdlib.h>
#include <pthread.h>
#include <algorithm>
#include <random>
#include "rbtree.h"
#include "URIParser.h"
#include "UpstreamPolicies.h"

class EndpointGroup
{
public:
	EndpointGroup(int group_id, UPSGroupPolicy *policy) :
			mutex(PTHREAD_MUTEX_INITIALIZER),
			gen(random())
	{
		this->id = group_id;
		this->policy = policy;
		this->nalives = 0;
		this->weight = 0;
	}

	EndpointAddress *get_one(WFNSTracing *tracing);
	EndpointAddress *get_one_backup(WFNSTracing *tracing);

public:
	int id;
	UPSGroupPolicy *policy;
	struct rb_node rb;
	pthread_mutex_t mutex;
	std::mt19937 gen;
	std::vector<EndpointAddress *> mains;
	std::vector<EndpointAddress *> backups;
	std::atomic<int> nalives;
	int weight;
};

UPSAddrParams::UPSAddrParams(const struct AddressParams *params,
							 const std::string& address) :
	PolicyAddrParams(params)
{
	this->weight = params->weight;
	this->server_type = params->server_type;
	this->group_id = params->group_id;

	if (this->group_id < 0)
		this->group_id = -1;

	if (this->weight == 0)
		this->weight = 1;
}

void UPSGroupPolicy::get_main_address(std::vector<std::string>& addr_list)
{
	UPSAddrParams *params;
	pthread_rwlock_rdlock(&this->rwlock);

	for (const EndpointAddress *server : this->servers)
	{
		params = static_cast<UPSAddrParams *>(server->params);
		if (params->server_type == 0)
			addr_list.push_back(server->address);
	}

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

inline bool UPSGroupPolicy::is_alive(const EndpointAddress *addr) const
{
	UPSAddrParams *params = static_cast<UPSAddrParams *>(addr->params);
	return ((params->group_id < 0 &&
				addr->fail_count < addr->params->max_fails) ||
			(params->group_id >= 0 &&
				params->group->nalives > 0));
}

void UPSGroupPolicy::recover_one_server(const EndpointAddress *addr)
{
	this->nalives++;
	UPSAddrParams *params = static_cast<UPSAddrParams *>(addr->params);
	params->group->nalives++;
}

void UPSGroupPolicy::fuse_one_server(const EndpointAddress *addr)
{
	this->nalives--;
	UPSAddrParams *params = static_cast<UPSAddrParams *>(addr->params);
	params->group->nalives--;
}

void UPSGroupPolicy::add_server(const std::string& address,
								const AddressParams *params)
{
	EndpointAddress *addr = new EndpointAddress(address,
									new UPSAddrParams(params, address));

	pthread_rwlock_wrlock(&this->rwlock);
	this->add_server_locked(addr);
	pthread_rwlock_unlock(&this->rwlock);
}

int UPSGroupPolicy::replace_server(const std::string& address,
								   const AddressParams *params)
{
	int ret;
	EndpointAddress *addr = new EndpointAddress(address,
									new UPSAddrParams(params, address));

	pthread_rwlock_wrlock(&this->rwlock);
	ret = this->remove_server_locked(address);
	this->add_server_locked(addr);
	pthread_rwlock_unlock(&this->rwlock);
	return ret;
}

bool UPSGroupPolicy::select(const ParsedURI& uri, WFNSTracing *tracing,
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

	// select_addr == NULL will happen only in consistent_hash
	EndpointAddress *select_addr = this->first_strategy(uri, tracing);

	if (!select_addr || select_addr->fail_count >= select_addr->params->max_fails)
	{
		if (select_addr)
			select_addr = this->check_and_get(select_addr, true, tracing);

		if (!select_addr && this->try_another)
			select_addr = this->another_strategy(uri, tracing);
	}

	if (!select_addr)
		select_addr = this->default_group->get_one_backup(tracing);

	if (select_addr)
	{
		*addr = select_addr;
		++select_addr->ref;
	}

	pthread_rwlock_unlock(&this->rwlock);
	return !!select_addr;
}

/*
 * addr_failed true: return an available one. If not exists, return NULL.
 * 			  false: means addr maybe group-alive.
 * 					 If addr is not available, get one from addr->group.
 */
EndpointAddress *UPSGroupPolicy::check_and_get(EndpointAddress *addr,
											   bool addr_failed,
											   WFNSTracing *tracing)
{
	UPSAddrParams *params = static_cast<UPSAddrParams *>(addr->params);

	if (addr_failed) // means fail_count >= max_fails
	{
		if (params->group_id == -1)
			return NULL;

		return params->group->get_one(tracing);
	}

	if (addr && addr->fail_count >= addr->params->max_fails &&
		params->group_id >= 0)
	{
		EndpointAddress *tmp = params->group->get_one(tracing);
		if (tmp)
			addr = tmp;
	}

	return addr;
}

EndpointAddress *EndpointGroup::get_one(WFNSTracing *tracing)
{
	if (this->nalives == 0)
		return NULL;

	EndpointAddress *server;
	EndpointAddress *addr = NULL;
	pthread_mutex_lock(&this->mutex);

	std::shuffle(this->mains.begin(), this->mains.end(), this->gen);
	for (size_t i = 0; i < this->mains.size(); i++)
	{
		server = this->mains[i];
		if (server->fail_count < server->params->max_fails &&
			WFServiceGovernance::in_select_history(tracing, server) == false)
		{
			addr = server;
			break;
		}
	}

	if (!addr)
	{
		std::shuffle(this->backups.begin(), this->backups.end(), this->gen);
		for (size_t i = 0; i < this->backups.size(); i++)
		{
			server = this->backups[i];
			if (server->fail_count < server->params->max_fails &&
				WFServiceGovernance::in_select_history(tracing, server) == false)
			{
				addr = server;
				break;
			}
		}
	}

	pthread_mutex_unlock(&this->mutex);
	return addr;
}

EndpointAddress *EndpointGroup::get_one_backup(WFNSTracing *tracing)
{
	if (this->nalives == 0)
		return NULL;

	EndpointAddress *server;
	EndpointAddress *addr = NULL;

	pthread_mutex_lock(&this->mutex);

	std::shuffle(this->backups.begin(), this->backups.end(), this->gen);
	for (size_t i = 0; i < this->backups.size(); i++)
	{
		server = this->backups[i];
		if (server->fail_count < server->params->max_fails &&
			WFServiceGovernance::in_select_history(tracing, server) == false)
		{
			addr = server;
			break;
		}
	}

	pthread_mutex_unlock(&this->mutex);
	return addr;
}

void UPSGroupPolicy::add_server_locked(EndpointAddress *addr)
{
	UPSAddrParams *params = static_cast<UPSAddrParams *>(addr->params);
	int group_id = params->group_id;
	rb_node **p = &this->group_map.rb_node;
	rb_node *parent = NULL;
	EndpointGroup *group;

	this->server_map[addr->address].push_back(addr);

	if (params->server_type == 0)
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
	params->group = group;
	this->recover_one_server(addr);
	if (params->server_type == 0)
	{
		group->mains.push_back(addr);
		group->weight += params->weight;
	}
	else
		group->backups.push_back(addr);
	pthread_mutex_unlock(&group->mutex);
}

int UPSGroupPolicy::remove_server_locked(const std::string& address)
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
			UPSAddrParams *params = static_cast<UPSAddrParams *>(addr->params);
			EndpointGroup *group = params->group;
			std::vector<EndpointAddress *> *vec;

			if (params->server_type == 0)
				vec = &group->mains;
			else
				vec = &group->backups;

			//std::lock_guard<std::mutex> lock(group->mutex);
			pthread_mutex_lock(&group->mutex);
			if (params->server_type == 0)
				group->weight -= params->weight;

			for (auto it = vec->begin(); it != vec->end(); ++it)
			{
				if (*it == addr)
				{
					vec->erase(it);
					break;
				}
			}

			if (--addr->ref == 0)
			{
				this->pre_delete_server(addr);
				delete addr;
			}

			pthread_mutex_unlock(&group->mutex);
			ret++;
		}

		this->server_map.erase(map_it);
	}

	return ret;
}

EndpointAddress *UPSGroupPolicy::consistent_hash_with_group(unsigned int hash,
															WFNSTracing *tracing)
{
	if (this->nalives == 0)
		return NULL;

	std::map<unsigned int, EndpointAddress *>::iterator it;
	it = this->addr_hash.lower_bound(hash);

	if (it == this->addr_hash.end())
		it = this->addr_hash.begin();

	while (!this->is_alive(it->second))
	{
		it++;
		if (it == this->addr_hash.end())
			it = this->addr_hash.begin();
	}

	return this->check_and_get(it->second, false, tracing);
}

void UPSGroupPolicy::hash_map_add_addr(EndpointAddress *addr)
{
	UPSAddrParams *params = static_cast<UPSAddrParams *>(addr->params);

	if (params->server_type == 0)
	{
		static std::hash<std::string> std_hash;
		unsigned int hash_value;
		size_t ip_count = this->server_map[addr->address].size();

		for (int i = 0; i < VIRTUAL_GROUP_SIZE * params->weight; i++)
		{
			hash_value = std_hash(addr->address + "|v" + std::to_string(i) +
								  "|n" + std::to_string(ip_count));
			this->addr_hash.insert(std::make_pair(hash_value, addr));
		}
	}
}

void UPSGroupPolicy::hash_map_remove_addr(const std::string& address)
{
	std::map<unsigned int, EndpointAddress *>::iterator it;

	for (it = this->addr_hash.begin(); it != this->addr_hash.end();)
	{
		if (it->second->address == address)
			this->addr_hash.erase(it++);
		else
			it++;
	}
}

int UPSRoundRobinPolicy::remove_server_locked(const std::string& address)
{
	if (servers.size() != 0)
	{
		size_t cur_idx = this->cur_idx % servers.size();

		for (size_t i = 0; i < cur_idx; i++)
		{
			if (this->servers[i]->address == address)
				this->cur_idx--;
		}
	}

	return UPSGroupPolicy::remove_server_locked(address);
}

EndpointAddress *UPSRoundRobinPolicy::first_strategy(const ParsedURI& uri,
													 WFNSTracing *tracing)
{
	return this->servers[this->cur_idx++ % this->servers.size()];
}

EndpointAddress *UPSRoundRobinPolicy::another_strategy(const ParsedURI& uri,
													   WFNSTracing *tracing)
{
	EndpointAddress *addr = this->servers[this->cur_idx++ % this->servers.size()];
	return this->check_and_get(addr, false, tracing);
}

void UPSWeightedRandomPolicy::add_server_locked(EndpointAddress *addr)
{
	UPSAddrParams *params = static_cast<UPSAddrParams *>(addr->params);

	UPSGroupPolicy::add_server_locked(addr);
	if (params->server_type == 0)
		this->total_weight += params->weight;
}

int UPSWeightedRandomPolicy::remove_server_locked(const std::string& address)
{
	UPSAddrParams *params;
	const auto map_it = this->server_map.find(address);

	if (map_it != this->server_map.cend())
	{
		for (EndpointAddress *addr : map_it->second)
		{
			params = static_cast<UPSAddrParams *>(addr->params);
			if (params->server_type == 0)
				this->total_weight -= params->weight;
		}
	}

	return UPSGroupPolicy::remove_server_locked(address);
}

int UPSWeightedRandomPolicy::select_history_weight(WFNSTracing *tracing)
{
	struct TracingData *tracing_data = (struct TracingData *)tracing->data;

	if (!tracing_data)
		return 0;

	int ret = 0;

	for (EndpointAddress *server : tracing_data->history)
		ret += ((UPSAddrParams *)server->params)->weight;

	return ret;
}

EndpointAddress *UPSWeightedRandomPolicy::first_strategy(const ParsedURI& uri,
														 WFNSTracing *tracing)
{
	int x = 0;
	int s = 0;
	size_t idx;
	UPSAddrParams *params;
	int temp_weight = this->total_weight;
	temp_weight -= UPSWeightedRandomPolicy::select_history_weight(tracing);

	if (temp_weight > 0)
		x = rand() % temp_weight;

	for (idx = 0; idx < this->servers.size(); idx++)
	{
		if (WFServiceGovernance::in_select_history(tracing, this->servers[idx]))
			continue;

		params = static_cast<UPSAddrParams *>(this->servers[idx]->params);
		s += params->weight;
		if (s > x)
			break;
	}
	if (idx == this->servers.size())
		idx--;

	return this->servers[idx];
}

EndpointAddress *UPSWeightedRandomPolicy::another_strategy(const ParsedURI& uri,
														   WFNSTracing *tracing)
{
	/* When all servers are down, recover all servers if any server
	 * reaches fusing timeout. */
	if (this->available_weight == 0)
		this->try_clear_breaker();

	int temp_weight = this->available_weight;
	if (temp_weight == 0)
		return NULL;

	UPSAddrParams *params;
	EndpointAddress *addr = NULL;
	int x = rand() % temp_weight;
	int s = 0;

	for (EndpointAddress *server : this->servers)
	{
		if (this->is_alive(server))
		{
			addr = server;
			params = static_cast<UPSAddrParams *>(server->params);
			s += params->weight;
			if (s > x)
				break;
		}
	}

	return this->check_and_get(addr, false, tracing);
}

void UPSWeightedRandomPolicy::recover_one_server(const EndpointAddress *addr)
{
	UPSAddrParams *params = static_cast<UPSAddrParams *>(addr->params);

	this->nalives++;
	if (params->group->nalives++ == 0 && params->group->id > 0)
		this->available_weight += params->group->weight;

	if (params->group_id < 0 && params->server_type == 0)
		this->available_weight += params->weight;
}

void UPSWeightedRandomPolicy::fuse_one_server(const EndpointAddress *addr)
{
	UPSAddrParams *params = static_cast<UPSAddrParams *>(addr->params);

	this->nalives--;
	if (--params->group->nalives == 0 && params->group->id > 0)
		this->available_weight -= params->group->weight;

	if (params->group_id < 0 && params->server_type == 0)
		this->available_weight -= params->weight;
}

EndpointAddress *UPSVNSWRRPolicy::first_strategy(const ParsedURI& uri,
												 WFNSTracing *tracing)
{
	int idx = this->cur_idx.fetch_add(1);
	int pos = 0;
	for (int i = 0; i < this->total_weight; i++, idx++)
	{
		pos = this->pre_generated_vec[idx % this->pre_generated_vec.size()];
		if (WFServiceGovernance::in_select_history(tracing, this->servers[pos]))
			continue;

		break;
	}
	return this->servers[pos];
}

void UPSVNSWRRPolicy::init_virtual_nodes()
{
	UPSAddrParams *params;
	size_t start_pos = this->pre_generated_vec.size();
	size_t end_pos = this->total_weight;
	this->pre_generated_vec.resize(end_pos);

	for (size_t i = start_pos; i < end_pos; i++)
	{
		for (size_t j = 0; j < this->servers.size(); j++)
		{
			const EndpointAddress *server = this->servers[j];
			params = static_cast<UPSAddrParams *>(server->params);
			this->current_weight_vec[j] += params->weight;
		}
		std::vector<int>::iterator biggest = std::max_element(this->current_weight_vec.begin(),
																 this->current_weight_vec.end());
		this->pre_generated_vec[i] = std::distance(this->current_weight_vec.begin(), biggest);
		this->current_weight_vec[this->pre_generated_vec[i]] -= this->total_weight;
	}
}

void UPSVNSWRRPolicy::init()
{
	if (this->total_weight <= 0)
		return;

	this->pre_generated_vec.clear();
	this->cur_idx = rand() % this->total_weight;
	std::vector<int> t(this->servers.size(), 0);
	this->current_weight_vec.swap(t);
	this->init_virtual_nodes();
}

void UPSVNSWRRPolicy::add_server_locked(EndpointAddress *addr)
{
	UPSWeightedRandomPolicy::add_server_locked(addr);
	init();
}

int UPSVNSWRRPolicy::remove_server_locked(const std::string& address)
{
	int ret = UPSWeightedRandomPolicy::remove_server_locked(address);
	init();
	return ret;
}

EndpointAddress *UPSConsistentHashPolicy::first_strategy(const ParsedURI& uri,
														 WFNSTracing *tracing)
{
	unsigned int hash_value = this->consistent_hash(
										uri.path ? uri.path : "",
										uri.query ? uri.query : "",
										uri.fragment ? uri.fragment : "");
	return this->consistent_hash_with_group(hash_value, tracing);
}

void UPSConsistentHashPolicy::add_server_locked(EndpointAddress *addr)
{
	UPSGroupPolicy::add_server_locked(addr);
	this->hash_map_add_addr(addr);
}

int UPSConsistentHashPolicy::remove_server_locked(const std::string& address)
{
	this->hash_map_remove_addr(address);

	return UPSGroupPolicy::remove_server_locked(address);
}

EndpointAddress *UPSManualPolicy::first_strategy(const ParsedURI& uri,
												 WFNSTracing *tracing)
{
	unsigned int idx = this->manual_select(uri.path ? uri.path : "",
										   uri.query ? uri.query : "",
										   uri.fragment ? uri.fragment : "");

	if (idx >= this->servers.size())
		idx %= this->servers.size();

	return this->servers[idx];
}

EndpointAddress *UPSManualPolicy::another_strategy(const ParsedURI& uri,
												   WFNSTracing *tracing)
{
	unsigned int hash_value = this->another_select(
										uri.path ? uri.path : "",
										uri.query ? uri.query : "",
										uri.fragment ? uri.fragment : "");
	return this->consistent_hash_with_group(hash_value, tracing);
}

void UPSManualPolicy::add_server_locked(EndpointAddress *addr)
{
	UPSGroupPolicy::add_server_locked(addr);

	if (this->try_another)
		this->hash_map_add_addr(addr);
}

int UPSManualPolicy::remove_server_locked(const std::string& address)
{
	if (this->try_another)
		this->hash_map_remove_addr(address);

	return UPSGroupPolicy::remove_server_locked(address);
}


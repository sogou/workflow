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

#include <pthread.h>
#include <algorithm>
#include "URIParser.h"
#include "StringUtil.h"
#include "UpstreamPolicies.h"

UPSAddress::UPSAddress(const std::string& address,
					   const struct AddressParams *address_params) :
	EndpointAddress(address, address_params)
{
	static std::hash<std::string> std_hash;
	for (int i = 0; i < VIRTUAL_GROUP_SIZE; i++)
		this->consistent_hash[i] = std_hash(address + "|v" + std::to_string(i));

	if (this->params.group_id < 0)
		this->params.group_id = -1;

	if (this->params.weight == 0)
		this->params.weight = 1;
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

bool UPSGroupPolicy::select(const ParsedURI& uri, UPSAddress **addr)
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
	const UPSAddress *select_addr = static_cast<const UPSAddress *>(this->first_stradegy(uri));

	if (!select_addr || select_addr->fail_count >= select_addr->params.max_fails)
	{
		if (select_addr)
			select_addr = this->check_and_get(select_addr, true);

		if (!select_addr && this->try_another)
		{
			select_addr = static_cast<const UPSAddress *>(this->another_stradegy(uri));
			select_addr = this->check_and_get(select_addr, false);
		}
	}

	if (!select_addr)
		this->default_group->get_one_backup();
	
	pthread_rwlock_unlock(&this->rwlock);

	if (select_addr)
	{
		*addr = (UPSAddress *)select_addr;
		return true;
	}

	return false;
}

// flag true : guarantee addr != NULL, and please return an available one
// flag false : means addr maybe useful but want one any way. addr may be NULL
inline const UPSAddress *UPSGroupPolicy::check_and_get(const UPSAddress *addr,
													   bool flag)
{
	if (flag == true) // && addr->fail_count >= addr->params.max_fails
	{
		if (addr->params.group_id == -1)
			return NULL;

		return addr->group->get_one();
	}

	if (addr && addr->fail_count >= addr->params.max_fails &&
		addr->params.group_id >= 0)
	{
		const UPSAddress *tmp = addr->group->get_one();
		if (tmp)
			addr = tmp;
	}

	return addr;
}

const UPSAddress *EndpointGroup::get_one()
{
	if (this->nalives == 0)
		return NULL;

	const UPSAddress *addr = NULL;
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

const UPSAddress *EndpointGroup::get_one_backup()
{
	if (this->nalives == 0)
		return NULL;

	const UPSAddress *addr = NULL;
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

void UPSGroupPolicy::add_server_locked(UPSAddress *addr)
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
	UPSAddress *addr;
	const auto map_it = this->server_map.find(address);

	if (map_it != this->server_map.cend())
	{
		for (EndpointAddress *server : map_it->second)
		{
			addr = static_cast<UPSAddress *>(server);
			EndpointGroup *group = addr->group;
			std::vector<UPSAddress *> *vec;

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

const UPSAddress *UPSGroupPolicy::consistent_hash_with_group(unsigned int hash)
{
	const UPSAddress *addr;
	const UPSAddress *select_addr = NULL;
	unsigned int min_dis = (unsigned int)-1;

	for (const EndpointAddress *server : this->servers)
	{
		addr = static_cast<const UPSAddress *>(server);
		if (this->is_alive_or_group_alive(addr))
		{
			for (int i = 0; i < VIRTUAL_GROUP_SIZE; i++)
			{
				unsigned int dis = std::min<unsigned int>
								   (hash - addr->consistent_hash[i],
								   addr->consistent_hash[i] - hash);

				if (dis < min_dis)
				{
					min_dis = dis;
					select_addr = addr;
				}
			}
		}
	}

	return this->check_and_get(select_addr, false);
}

void UPSWeightedRandomPolicy::add_server_locked(UPSAddress *addr)
{
	UPSGroupPolicy::add_server_locked(addr);
	if (addr->params.server_type == 0)
		this->total_weight += addr->params.weight;
	return;
}

int UPSWeightedRandomPolicy::remove_server_locked(const std::string& address)
{
	UPSAddress *addr;
	const auto map_it = this->server_map.find(address);

	if (map_it != this->server_map.cend())
	{
		for (EndpointAddress *server : map_it->second)
		{
			addr = static_cast<UPSAddress *>(server);
			if (addr->params.server_type == 0)
				this->total_weight -= addr->params.weight;
		}
	}

	return UPSGroupPolicy::remove_server_locked(address);
}

const UPSAddress *UPSWeightedRandomPolicy::first_stradegy(const ParsedURI& uri)
{
	int x = 0;
	int s = 0;
	size_t idx;
	const UPSAddress *addr;
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

	addr = static_cast<const UPSAddress *>(this->servers[idx]);
	return addr;
}

const UPSAddress *UPSWeightedRandomPolicy::another_stradegy(const ParsedURI& uri)
{
	int temp_weight = this->available_weight;
	if (temp_weight == 0)
		return NULL;

	const UPSAddress *addr;
	const UPSAddress *select_addr = NULL;
	int x = rand() % temp_weight;
	int s = 0;

	for (const EndpointAddress *server : this->servers)
	{
		addr = static_cast<const UPSAddress *>(server);
		if (this->is_alive_or_group_alive(addr))
		{
			select_addr = addr;
			s += addr->params.weight;
			if (s > x)
				break;
		}
	}

	return this->check_and_get(select_addr, false);
}

void UPSWeightedRandomPolicy::recover_one_server(const UPSAddress *addr)
{
	this->nalives++;
	if (addr->group->nalives++ == 0 && addr->group->id > 0)
		this->available_weight += addr->group->weight;

	if (addr->params.group_id < 0 && addr->params.server_type == 0)
		this->available_weight += addr->params.weight;
}

void UPSWeightedRandomPolicy::fuse_one_server(const UPSAddress *addr)
{
	this->nalives--;
	if (--addr->group->nalives == 0 && addr->group->id > 0)
		this->available_weight -= addr->group->weight;

	if (addr->params.group_id < 0 && addr->params.server_type == 0)
		this->available_weight -= addr->params.weight;
}

const UPSAddress *UPSConsistentHashPolicy::first_stradegy(const ParsedURI& uri)
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

const UPSAddress *UPSManualPolicy::first_stradegy(const ParsedURI& uri)
{
	unsigned int idx = this->manual_select(uri.path ? uri.path : "",
										   uri.query ? uri.query : "",
										   uri.fragment ? uri.fragment : ""); 

	if (idx >= this->servers.size())
		idx %= this->servers.size();

	const UPSAddress *addr = static_cast<const UPSAddress *>(this->servers[idx]);
	return addr;
}

const UPSAddress *UPSManualPolicy::another_stradegy(const ParsedURI& uri)
{
	unsigned int hash_value;

	if (this->try_another_select)
		hash_value = this->try_another_select(uri.path ? uri.path : "",
											  uri.query ? uri.query : "",
											  uri.fragment ? uri.fragment : "");
	else
		hash_value = UPSConsistentHashPolicy::default_consistent_hash(
												uri.path ? uri.path : "",
												uri.query ? uri.query : "",
												uri.fragment ? uri.fragment : "");
	return this->consistent_hash_with_group(hash_value);
}


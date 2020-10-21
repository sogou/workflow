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

  Authors: Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <functional>
#include <chrono>
#include "list.h"
#include "rbtree.h"
#include "URIParser.h"
#include "StringUtil.h"
#include "EndpointParams.h"
#include "UpstreamManager.h"

#define GET_CURRENT_SECOND	std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count()
#define MTTR_SECOND			30
#define VIRTUAL_GROUP_SIZE	16

namespace //anoymous namespace, for safe, avoid conflict
{
// RAII: YES
class ReadLock
{
public:
	ReadLock(pthread_rwlock_t& rwlock): rwlock_(&rwlock) { pthread_rwlock_rdlock(rwlock_); }
	ReadLock(pthread_rwlock_t *rwlock): rwlock_(rwlock) { pthread_rwlock_rdlock(rwlock_); }
	~ReadLock() { pthread_rwlock_unlock(rwlock_); }

private:
	pthread_rwlock_t *rwlock_;
};

// RAII: YES
class WriteLock
{
public:
	WriteLock(pthread_rwlock_t& rwlock): rwlock_(&rwlock) { pthread_rwlock_wrlock(rwlock_); }
	WriteLock(pthread_rwlock_t *rwlock): rwlock_(rwlock) { pthread_rwlock_wrlock(rwlock_); }
	~WriteLock() { pthread_rwlock_unlock(rwlock_); }

private:
	pthread_rwlock_t *rwlock_;
};

}

class UpstreamAddress;
class UpstreamGroup;
class Upstream;

class UpstreamAddress
{
public:
	UpstreamGroup *group;
	AddressParams params;
	struct list_head list;
	int64_t broken_timeout;
	unsigned int consistent_hash[VIRTUAL_GROUP_SIZE];
	std::string address;
	std::string host;
	std::string port;
	std::atomic<unsigned int> fail_count;
	unsigned short port_value;

public:
	UpstreamAddress(const std::string& address,
					const struct AddressParams *address_params);
};

class UpstreamGroup
{
public:
	Upstream *upstream;
	struct rb_node rb;
	std::mutex mutex;
	std::vector<UpstreamAddress *> mains;
	std::vector<UpstreamAddress *> backups;
	struct list_head breaker_list;
	std::atomic<int> nbreak;
	std::atomic<int> nalive;
	int weight;
	int group_id;

public:
	UpstreamGroup(int group_id, Upstream *us):
		upstream(us),
		nbreak(0),
		nalive(0),
		weight(0),
		group_id(group_id)
	{
		INIT_LIST_HEAD(&this->breaker_list);
	}

	const UpstreamAddress *get_one();
	const UpstreamAddress *get_one_backup();
};

class Upstream
{
public:
	Upstream();
	~Upstream();

	int add(UpstreamAddress *ua);
	int del(const std::string& address);
	void disable_server(const std::string& address);
	void enable_server(const std::string& address);
	const UpstreamAddress *get(const ParsedURI& uri);
	int set_select_callback(upstream_route_t&& select_callback);
	int set_consistent_mode(upstream_route_t&& consistent_callback);
	int set_attr(bool try_another, upstream_route_t rehash_callback);
	void check_one_breaker(UpstreamGroup *group, int64_t cur_time);
	void check_all_breaker();
	void get_all_main(std::vector<std::string>& addr_list);

	static void notify_unavailable(UpstreamAddress *ua);
	static void notify_available(UpstreamAddress *ua);

protected:
	pthread_rwlock_t rwlock_;
	int total_weight_;
	int available_weight_;
	std::vector<UpstreamAddress *> mains_;
	std::unordered_map<std::string, std::vector<UpstreamAddress *>> server_map_;
	struct rb_root group_map_;
	upstream_route_t select_callback_;
	upstream_route_t consistent_callback_;
	UpstreamGroup *default_group_;
	bool try_another_;
	bool is_consistent_;

private:
	void lose_one_server(UpstreamGroup *group, const UpstreamAddress *ua);
	void gain_one_server(UpstreamGroup *group, const UpstreamAddress *ua);
	const UpstreamAddress *weighted_random_try_another() const;
	const UpstreamAddress *consistent_hash_select(unsigned int hash) const;
};

const UpstreamAddress *UpstreamGroup::get_one()
{
	if (this->nalive == 0)
		return NULL;

	std::lock_guard<std::mutex> lock(this->mutex);

	std::random_shuffle(this->mains.begin(), this->mains.end());
	for (const auto *main : this->mains)
	{
		if (main->fail_count < main->params.max_fails)
			return main;
	}

	std::random_shuffle(this->backups.begin(), this->backups.end());
	for (const auto *backup : this->backups)
	{
		if (backup->fail_count < backup->params.max_fails)
			return backup;
	}

	return NULL;
}

const UpstreamAddress *UpstreamGroup::get_one_backup()
{
	if (this->nalive == 0)
		return NULL;

	std::lock_guard<std::mutex> lock(this->mutex);

	std::random_shuffle(this->backups.begin(), this->backups.end());
	for (const auto *backup : this->backups)
	{
		if (backup->fail_count < backup->params.max_fails)
			return backup;
	}

	return NULL;
}

static unsigned int __default_consistent_hash(const char *path,
											  const char *query,
											  const char *fragment)
{
	static std::hash<std::string> std_hash;
	std::string str(path);

	str += query;
	str += fragment;
	return std_hash(str);
}

UpstreamAddress::UpstreamAddress(const std::string& address,
								 const struct AddressParams *address_params)
{
	static std::hash<std::string> std_hash;
	std::vector<std::string> arr = StringUtil::split(address, ':');

	this->list.next = NULL;
	this->fail_count = 0;
	this->params = *address_params;
	this->address = address;
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

Upstream::Upstream():
	rwlock_(PTHREAD_RWLOCK_INITIALIZER),
	total_weight_(0),
	available_weight_(0),
	select_callback_(nullptr),
	consistent_callback_(nullptr),
	try_another_(false),
	is_consistent_(false)
{
	group_map_.rb_node = NULL;
	default_group_ = new UpstreamGroup(-1, this);
	rb_link_node(&default_group_->rb, NULL, &group_map_.rb_node);
	rb_insert_color(&default_group_->rb, &group_map_);
}

Upstream::~Upstream()
{
	UpstreamGroup *group;

	while (group_map_.rb_node)
	{
		group = rb_entry(group_map_.rb_node, UpstreamGroup, rb);
		rb_erase(group_map_.rb_node, &group_map_);
		delete group;
	}
}

void Upstream::lose_one_server(UpstreamGroup *group, const UpstreamAddress *ua)
{
	if (--group->nalive == 0 && ua->params.group_id >= 0)
		available_weight_ -= group->weight;

	if (ua->params.group_id < 0 && ua->params.server_type == 0)
		available_weight_ -= ua->params.weight;
}

void Upstream::gain_one_server(UpstreamGroup *group, const UpstreamAddress *ua)
{
	if (group->nalive++ == 0 && ua->params.group_id >= 0)
		available_weight_ += group->weight;

	if (ua->params.group_id < 0 && ua->params.server_type == 0)
		available_weight_ += ua->params.weight;
}

int Upstream::add(UpstreamAddress *ua)
{
	int group_id = ua->params.group_id;
	rb_node **p = &group_map_.rb_node;
	rb_node *parent = NULL;
	UpstreamGroup *group;
	WriteLock lock(rwlock_);

	server_map_[ua->address].push_back(ua);
	while (*p)
	{
		parent = *p;
		group = rb_entry(*p, UpstreamGroup, rb);

		if (group_id < group->group_id)
			p = &(*p)->rb_left;
		else if (group_id > group->group_id)
			p = &(*p)->rb_right;
		else
			break;
	}

	if (*p == NULL)
	{
		group = new UpstreamGroup(group_id, this);
		rb_link_node(&group->rb, parent, p);
		rb_insert_color(&group->rb, &group_map_);
	}

	if (ua->params.server_type == 0)
	{
		total_weight_ += ua->params.weight;
		mains_.push_back(ua);
	}

	group->mutex.lock();
	gain_one_server(group, ua);
	ua->group = group;
	if (ua->params.server_type == 0)
	{
		group->weight += ua->params.weight;
		group->mains.push_back(ua);
	}
	else
		group->backups.push_back(ua);

	group->mutex.unlock();

	return 0;
}

int Upstream::del(const std::string& address)
{
	WriteLock lock(rwlock_);
	const auto map_it = server_map_.find(address);

	if (map_it != server_map_.cend())
	{
		for (auto ua : map_it->second)
		{
			auto *group = ua->group;
			std::vector<UpstreamAddress *> *vec;

			if (ua->params.server_type == 0)
			{
				total_weight_ -= ua->params.weight;
				vec = &group->mains;
			}
			else
				vec = &group->backups;

			std::lock_guard<std::mutex> lock(group->mutex);

			ua->group = NULL;
			if (ua->fail_count < ua->params.max_fails)
				lose_one_server(group, ua);

			if (ua->params.server_type == 0)
				group->weight -= ua->params.weight;

			for (auto it = vec->begin(); it != vec->end(); ++it)
			{
				if (*it == ua)
				{
					vec->erase(it);
					break;
				}
			}
		}

		server_map_.erase(map_it);
	}

	int n = (int)mains_.size();
	int new_n = 0;

	for (int i = 0; i < n; i++)
	{
		if (mains_[i]->address != address)
		{
			if (new_n != i)
				mains_[new_n++] = mains_[i];
			else
				new_n++;
		}
	}

	if (new_n < n)
	{
		mains_.resize(new_n);
		return n - new_n;
	}

	return 0;
}

void Upstream::disable_server(const std::string& address)
{
	ReadLock lock(rwlock_);
	const auto map_it = server_map_.find(address);

	if (map_it != server_map_.cend())
	{
		for (auto ua : map_it->second)
		{
			auto *group = ua->group;

			if (group)
			{
				std::lock_guard<std::mutex> lock(group->mutex);

				ua->fail_count = ua->params.max_fails;
				if (ua->group == group && !ua->list.next)
				{
					ua->broken_timeout = GET_CURRENT_SECOND + MTTR_SECOND;
					list_add_tail(&ua->list, &group->breaker_list);
					group->nbreak++;
					group->upstream->lose_one_server(group, ua);
				}
			}
			else
				ua->fail_count = ua->params.max_fails;
		}
	}
}

void Upstream::enable_server(const std::string& address)
{
	ReadLock lock(rwlock_);
	const auto map_it = server_map_.find(address);

	if (map_it != server_map_.cend())
	{
		for (auto ua : map_it->second)
			UpstreamManager::notify_available(ua);
	}
}

void Upstream::get_all_main(std::vector<std::string>& addr_list)
{
	ReadLock lock(rwlock_);

	for (const auto *main : mains_)
		addr_list.push_back(main->address);
}

static inline const UpstreamAddress *__check_get_strong(const UpstreamAddress *ua)
{
	if (ua->fail_count >= ua->params.max_fails)
	{
		if (ua->params.group_id < 0)
			ua = NULL;
		else
			ua = ua->group->get_one();
	}

	return ua;
}

static inline const UpstreamAddress *__check_get_weak(const UpstreamAddress *ua)
{
	if (ua && ua->fail_count >= ua->params.max_fails && ua->params.group_id >= 0)
	{
		const auto *ret = ua->group->get_one();

		if (ret)
			ua = ret;
	}

	return ua;
}

static inline bool __is_alive_or_group_alive(const UpstreamAddress *ua)
{
	return (ua->params.group_id >= 0 && ua->group->nalive > 0)
		|| (ua->params.group_id < 0 && ua->fail_count < ua->params.max_fails);
}

const UpstreamAddress *Upstream::weighted_random_try_another() const
{
	int temp_weight = available_weight_;

	if (temp_weight == 0)
		return NULL;

	const UpstreamAddress *ua = NULL;
	int x = rand() % temp_weight;
	int s = 0;

	for (const auto *main : mains_)
	{
		if (__is_alive_or_group_alive(main))
		{
			ua = main;
			s += main->params.weight;
			if (s > x)
				break;
		}
	}

	return __check_get_weak(ua);
}

const UpstreamAddress *Upstream::consistent_hash_select(unsigned int hash) const
{
	const UpstreamAddress *ua = NULL;
	unsigned int min_dis = (unsigned int)-1;

	for (const auto *main : mains_)
	{
		if (__is_alive_or_group_alive(main))
		{
			for (int i = 0; i < VIRTUAL_GROUP_SIZE; i++)
			{
				unsigned int dis = std::min<unsigned int>
										   (hash - main->consistent_hash[i],
											main->consistent_hash[i] - hash);

				if (dis < min_dis)
				{
					min_dis = dis;
					ua = main;
				}
			}
		}
	}

	return __check_get_weak(ua);
}

void Upstream::check_one_breaker(UpstreamGroup *group, int64_t cur_time)
{
	struct list_head *pos, *tmp;
	UpstreamAddress *ua;

	if (group->nbreak == 0)
		return;

	std::lock_guard<std::mutex> lock(group->mutex);

	list_for_each_safe(pos, tmp, &group->breaker_list)
	{
		ua = list_entry(pos, UpstreamAddress, list);
		if (cur_time >= ua->broken_timeout)
		{
			if (ua->fail_count >= ua->params.max_fails)
			{
				ua->fail_count = ua->params.max_fails - 1;
				if (ua->group == group)
					gain_one_server(group, ua);
			}

			list_del(pos);
			ua->list.next = NULL;
			group->nbreak--;
		}
	}
}

void Upstream::check_all_breaker()
{
	if (!group_map_.rb_node)
		return;

	struct rb_node *cur = rb_first(&group_map_);
	UpstreamGroup *group;
	int64_t cur_time = GET_CURRENT_SECOND;

	while (cur)
	{
		group = rb_entry(cur, UpstreamGroup, rb);
		check_one_breaker(group, cur_time);
		cur = rb_next(cur);
	}
}

const UpstreamAddress *Upstream::get(const ParsedURI& uri)
{
	unsigned int idx;
	unsigned int hash_value;
	const UpstreamAddress *ua;

	if (is_consistent_)// consistent mode
	{
		if (consistent_callback_)
			hash_value = consistent_callback_(uri.path ? uri.path : "",
											  uri.query ? uri.query : "",
											  uri.fragment ? uri.fragment : "");
		else
			hash_value = __default_consistent_hash(uri.path ? uri.path : "",
												   uri.query ? uri.query : "",
												   uri.fragment ? uri.fragment : "");

		ReadLock lock(rwlock_);
		check_all_breaker();
		ua = consistent_hash_select(hash_value);
	}
	else
	{
		ReadLock lock(rwlock_);
		unsigned int n = (unsigned int)mains_.size();

		if (n == 0)
			return NULL;
		else if (n == 1)
			idx = 0;
		else if (select_callback_)
		{
			idx = select_callback_(uri.path ? uri.path : "",
								   uri.query ? uri.query : "",
								   uri.fragment ? uri.fragment : "");

			if (idx >= n)
				idx %= n;
		}
		else
		{
			int x = 0;
			int s = 0;
			int temp_weight = total_weight_;

			if (temp_weight > 0)
				x = rand() % temp_weight;

			for (idx = 0; idx < n; idx++)
			{
				s += mains_[idx]->params.weight;
				if (s > x)
					break;
			}

			if (idx == n)
				idx = n - 1;
		}

		ua = mains_[idx];
		if (ua->fail_count >= ua->params.max_fails)
		{
			check_all_breaker();
			ua = __check_get_strong(ua);

			if (!ua && try_another_)
			{
				if (!select_callback_)// weighted random mode
					ua = weighted_random_try_another();
				else// manual mode
				{
					if (consistent_callback_)
						hash_value = consistent_callback_(uri.path ? uri.path : "",
														  uri.query ? uri.query : "",
														  uri.fragment ? uri.fragment : "");
					else
						hash_value = __default_consistent_hash(uri.path ? uri.path : "",
															   uri.query ? uri.query : "",
															   uri.fragment ? uri.fragment : "");

					ua = consistent_hash_select(hash_value);
				}
			}
		}
	}

	if (!ua)
		ua = default_group_->get_one_backup();//get one backup from group[-1]

	return ua;
}

int Upstream::set_select_callback(upstream_route_t&& select_callback)
{
	WriteLock lock(rwlock_);

	select_callback_ = std::move(select_callback);
	return 0;
}

int Upstream::set_consistent_mode(upstream_route_t&& consistent_callback)
{
	WriteLock lock(rwlock_);

	is_consistent_ = true;
	consistent_callback_ = std::move(consistent_callback);
	return 0;
}

int Upstream::set_attr(bool try_another, upstream_route_t rehash_callback)
{
	WriteLock lock(rwlock_);

	try_another_ = try_another;
	consistent_callback_ = std::move(rehash_callback);
	return 0;
}

void Upstream::notify_unavailable(UpstreamAddress *ua)
{
	auto *group = ua->group;

	if (group)
	{
		std::lock_guard<std::mutex> lock(group->mutex);

		if (++ua->fail_count == ua->params.max_fails && ua->group == group && !ua->list.next)
		{
			ua->broken_timeout = GET_CURRENT_SECOND + MTTR_SECOND;
			list_add_tail(&ua->list, &group->breaker_list);
			group->nbreak++;
			group->upstream->lose_one_server(group, ua);
		}
	}
	else
		++ua->fail_count;
}

void Upstream::notify_available(UpstreamAddress *ua)
{
	auto *group = ua->group;

	if (group)
	{
		std::lock_guard<std::mutex> lock(group->mutex);

		if (ua->list.next) // in the list
		{
			if (ua->group == group && ua->fail_count >= ua->params.max_fails)
				group->upstream->gain_one_server(group, ua);

			list_del(&ua->list);
			ua->list.next = NULL;
		}

		ua->fail_count = 0;
	}
	else
		ua->fail_count = 0;
}

class __UpstreamManager
{
public:
	static __UpstreamManager *get_instance()
	{
		static __UpstreamManager kInstance;
		return &kInstance;
	}

	int upstream_create(const std::string& name,
						upstream_route_t&& consistent_hash)
	{
		Upstream *upstream = NULL;
		{
			WriteLock lock(rwlock_);

			if (upstream_map_.find(name) == upstream_map_.end())
				upstream = &upstream_map_[name];
		}

		if (upstream)
			return upstream->set_consistent_mode(std::move(consistent_hash));

		return -1;
	}

	int upstream_create(const std::string& name, bool try_another)
	{
		Upstream *upstream = NULL;
		{
			WriteLock lock(rwlock_);

			if (upstream_map_.find(name) == upstream_map_.end())
				upstream = &upstream_map_[name];
		}

		if (upstream)
			return upstream->set_attr(try_another, nullptr);

		return -1;
	}

	int upstream_create(const std::string& name,
						upstream_route_t&& select,
						bool try_another,
						upstream_route_t&& consistent_hash)
	{
		Upstream *upstream = NULL;
		{
			WriteLock lock(rwlock_);

			if (upstream_map_.find(name) == upstream_map_.end())
				upstream = &upstream_map_[name];
		}

		if (upstream)
		{
			upstream->set_select_callback(std::move(select));
			upstream->set_attr(try_another, std::move(consistent_hash));
			return 0;
		}

		return 0;
	}

	int upstream_add_server(const std::string& name,
							const std::string& address,
							const AddressParams *address_params)
	{
		auto *ua = new UpstreamAddress(address, address_params);
		{
			WriteLock lock(rwlock_);

			addresses_.push_back(ua);
		}

		Upstream *upstream = NULL;
		{
			ReadLock lock(rwlock_);
			auto it = upstream_map_.find(name);

			if (it != upstream_map_.end())
				upstream = &it->second;
		}

		if (upstream)
			return upstream->add(ua);

		return -1;
	}

	int upstream_remove_server(const std::string& name, const std::string& address)
	{
		Upstream *upstream = NULL;
		{
			ReadLock lock(rwlock_);
			auto it = upstream_map_.find(name);

			if (it != upstream_map_.end())
				upstream = &it->second;
		}

		if (upstream)
			return upstream->del(address);

		return -1;
	}

	int upstream_replace_server(const std::string& name,
								const std::string& address,
								const AddressParams *address_params)
	{
		Upstream *upstream = NULL;
		auto *ua = new UpstreamAddress(address, address_params);
		WriteLock lock(rwlock_);

		addresses_.push_back(ua);
		auto it = upstream_map_.find(name);

		if (it != upstream_map_.end())
			upstream = &it->second;

		if (upstream)
		{
			upstream->del(address);
			return upstream->add(ua);
		}

		return -1;
	}

	int upstream_disable_server(const std::string& name, const std::string& address)
	{
		Upstream *upstream = NULL;
		{
			ReadLock lock(rwlock_);
			auto it = upstream_map_.find(name);

			if (it != upstream_map_.end())
				upstream = &it->second;
		}

		if (upstream)
		{
			upstream->disable_server(address);
			return 0;
		}

		return -1;
	}

	int upstream_enable_server(const std::string& name, const std::string& address)
	{
		Upstream *upstream = NULL;
		{
			ReadLock lock(rwlock_);
			auto it = upstream_map_.find(name);

			if (it != upstream_map_.end())
				upstream = &it->second;
		}

		if (upstream)
		{
			upstream->enable_server(address);
			return 0;
		}

		return -1;
	}

	std::vector<std::string> upstream_main_address_list(const std::string& name)
	{
		std::vector<std::string> addr_list;
		Upstream *upstream = NULL;
		{
			ReadLock lock(rwlock_);
			auto it = upstream_map_.find(name);

			if (it != upstream_map_.end())
				upstream = &it->second;
		}

		if (upstream)
			upstream->get_all_main(addr_list);

		return addr_list;
	}

	int upstream_delete(const std::string& name)
	{
		WriteLock lock(rwlock_);
		const auto it = upstream_map_.find(name);

		if (it == upstream_map_.end())
			return 0;
		else
			upstream_map_.erase(it);

		return 1;
	}

	int upstream_choose(ParsedURI& uri, UpstreamManager::UpstreamResult& result)
	{
		result.cookie = NULL;
		result.address_params = NULL;
		result.state = UPSTREAM_NOTFOUND;

		if (uri.state != URI_STATE_SUCCESS || !uri.host)
			return 0;// UPSTREAM_NOTFOUND

		Upstream *upstream;
		{
			ReadLock lock(rwlock_);
			auto it = upstream_map_.find(uri.host);

			if (it == upstream_map_.end())
				return 0;// UPSTREAM_NOTFOUND

			upstream = &it->second;
		}

		const auto *ua = upstream->get(uri);

		if (!ua)
		{
			result.state = UPSTREAM_ALL_DOWN;
			return 0;
		}

		char *host = NULL;
		char *port = NULL;

		if (!ua->host.empty())
		{
			host = strdup(ua->host.c_str());
			if (!host)
				return -1;
		}

		if (ua->port_value > 0)
		{
			port = strdup(ua->port.c_str());
			if (!port)
			{
				free(host);
				return -1;
			}

			free(uri.port);
			uri.port = port;
		}

		free(uri.host);
		uri.host = host;

		result.state = UPSTREAM_SUCCESS;
		result.address_params = &ua->params;
		result.cookie = const_cast<UpstreamAddress *>(ua);
		return 0;
	}

private:
	__UpstreamManager():
		rwlock_(PTHREAD_RWLOCK_INITIALIZER)
	{}

	~__UpstreamManager()
	{
		for (auto *ua : addresses_)
			delete ua;
	}

private:
	pthread_rwlock_t rwlock_;
	std::unordered_map<std::string, Upstream> upstream_map_;
	std::vector<UpstreamAddress *> addresses_;
};

int UpstreamManager::upstream_create_consistent_hash(const std::string& name,
													 upstream_route_t consitent_hash)
{
	auto *manager = __UpstreamManager::get_instance();

	return manager->upstream_create(name, std::move(consitent_hash));
}

int UpstreamManager::upstream_create_weighted_random(const std::string& name,
													 bool try_another)
{
	auto *manager = __UpstreamManager::get_instance();

	return manager->upstream_create(name, try_another);
}

int UpstreamManager::upstream_create_manual(const std::string& name,
											upstream_route_t select,
											bool try_another,
											upstream_route_t consitent_hash)
{
	auto *manager = __UpstreamManager::get_instance();

	return manager->upstream_create(name, std::move(select),
									try_another, std::move(consitent_hash));
}

int UpstreamManager::upstream_add_server(const std::string& name,
										 const std::string& address)
{
	auto *manager = __UpstreamManager::get_instance();

	return manager->upstream_add_server(name, address, &ADDRESS_PARAMS_DEFAULT);
}

int UpstreamManager::upstream_add_server(const std::string& name,
										 const std::string& address,
										 const AddressParams *address_params)
{
	auto *manager = __UpstreamManager::get_instance();

	return manager->upstream_add_server(name, address, address_params);
}

int UpstreamManager::upstream_remove_server(const std::string& name,
											const std::string& address)
{
	auto *manager = __UpstreamManager::get_instance();

	return manager->upstream_remove_server(name, address);
}

int UpstreamManager::upstream_replace_server(const std::string& name,
											 const std::string& address,
											 const AddressParams *address_params)
{
	auto *manager = __UpstreamManager::get_instance();

	return manager->upstream_replace_server(name, address, address_params);
}

int UpstreamManager::upstream_disable_server(const std::string& name,
											 const std::string& address)
{
	auto *manager = __UpstreamManager::get_instance();

	return manager->upstream_disable_server(name, address);
}

int UpstreamManager::upstream_enable_server(const std::string& name,
											const std::string& address)
{
	auto *manager = __UpstreamManager::get_instance();

	return manager->upstream_enable_server(name, address);
}

std::vector<std::string> UpstreamManager::upstream_main_address_list(const std::string& name)
{
	auto *manager = __UpstreamManager::get_instance();

	return manager->upstream_main_address_list(name);
}

int UpstreamManager::upstream_delete(const std::string& name)
{
	auto *manager = __UpstreamManager::get_instance();

	return manager->upstream_delete(name);
}

int UpstreamManager::choose(ParsedURI& uri, UpstreamResult& result)
{
	auto *manager = __UpstreamManager::get_instance();

	return manager->upstream_choose(uri, result);
}

void UpstreamManager::notify_unavailable(void *cookie)
{
	if (cookie)
		Upstream::notify_unavailable((UpstreamAddress *)cookie);
}

void UpstreamManager::notify_available(void *cookie)
{
	if (cookie)
		Upstream::notify_available((UpstreamAddress *)cookie);
}


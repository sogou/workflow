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

#ifndef _UPSTREAM_POLICIES_H_
#define _UPSTREAM_POLICIES_H_ 

#include <mutex>
#include <unordered_map>
#include <vector>
#include <atomic>
#include "URIParser.h"
#include "RWLock.h"
#include "EndpointParams.h"
#include "WFNameService.h"
#include "WFDNSResolver.h"
#include "WFGlobal.h"
#include "WFTaskError.h"
#include "UpstreamManager.h"

#define MTTR_SECOND			30
#define VIRTUAL_GROUP_SIZE  16

#define GET_CURRENT_SECOND  std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count()

class EndpointGroup;
class UPSPolicy;
class UPSGroupPolicy;

class EndpointAddress
{
public:
	EndpointGroup *group;
	AddressParams params;
	std::string address;
	std::string host;
	std::string port;
	short port_value;
	struct list_head list;
	std::atomic<unsigned int> fail_count;
	long long broken_timeout;
	unsigned int consistent_hash[VIRTUAL_GROUP_SIZE];

public:
	EndpointAddress(const std::string& address,
					const struct AddressParams *address_params);
};

class EndpointGroup
{
public:
	int id;
	UPSGroupPolicy *policy;
	struct rb_node rb;
	std::mutex mutex;
	std::vector<EndpointAddress *> mains;
	std::vector<EndpointAddress *> backups;
	std::atomic<int> nalives;
	int weight;

	EndpointGroup(int group_id, UPSGroupPolicy *policy)
	{
		this->id = group_id;
		this->policy = policy;
		this->nalives = 0;
		this->weight = 0;
	}

public:
	const EndpointAddress *get_one();
	const EndpointAddress *get_one_backup();
};

class UPSPolicy : public WFDNSResolver
{
public:
	virtual WFRouterTask *create_router_task(const struct WFNSParams *params,
											 router_callback_t callback);
	virtual void success(RouteManager::RouteResult *result, void *cookie,
					 	 CommTarget *target);
	virtual void failed(RouteManager::RouteResult *result, void *cookie,
						CommTarget *target);

	void add_server(const std::string& address, const AddressParams *address_params);
	int remove_server(const std::string& address);
	int replace_server(const std::string& address, const AddressParams *address_params);

	virtual void enable_server(const std::string& address);
	virtual void disable_server(const std::string& address);
	virtual void get_main_address(std::vector<std::string>& addr_list);
	// virtual void server_list_change(/* std::vector<server> status */) {}

public:
	UPSPolicy()
	{
		this->nalives = 0;
		this->try_another = false;
		INIT_LIST_HEAD(&this->breaker_list);
	}

	virtual ~UPSPolicy()
	{
		for (EndpointAddress *addr : this->addresses)
			delete addr;
	}

private:
	virtual bool select(const ParsedURI& uri, EndpointAddress **addr);

	virtual void recover_one_server(const EndpointAddress *addr)
	{
		this->nalives++;
	}

	virtual void fuse_one_server(const EndpointAddress *addr)
	{
		this->nalives--;
	}

	virtual void add_server_locked(EndpointAddress *addr);
	virtual int remove_server_locked(const std::string& address);

	void recover_server_from_breaker(EndpointAddress *addr);
	void fuse_server_to_breaker(EndpointAddress *addr);

	struct list_head breaker_list;
	std::mutex breaker_lock;

protected:
	virtual const EndpointAddress *first_stradegy(const ParsedURI& uri);
	virtual const EndpointAddress *another_stradegy(const ParsedURI& uri);
	void check_breaker();

	std::vector<EndpointAddress *> servers; // current servers
	std::vector<EndpointAddress *> addresses; // memory management
	std::unordered_map<std::string,
					   std::vector<EndpointAddress *>> server_map;
	RWLock rwlock;
	std::atomic<int> nalives;
	bool try_another;
};

class UPSGroupPolicy : public UPSPolicy
{
public:
	UPSGroupPolicy();
	~UPSGroupPolicy();

protected:
	struct rb_root group_map;
	EndpointGroup *default_group;

private:
	virtual void recover_one_server(const EndpointAddress *addr)
	{
		this->nalives++;
		addr->group->nalives++;
	}

	virtual void fuse_one_server(const EndpointAddress *addr)
	{
		this->nalives--;
		addr->group->nalives--;
	}

	virtual bool select(const ParsedURI& uri, EndpointAddress **addr);

protected:
	virtual void add_server_locked(EndpointAddress *addr);
	virtual int remove_server_locked(const std::string& address);

	const EndpointAddress *consistent_hash_with_group(unsigned int hash) const;

 	// check_get_weak
	inline const EndpointAddress *check_and_get(const EndpointAddress *addr) const
	{
		if (addr && addr->fail_count >= addr->params.max_fails &&
			addr->params.group_id >= 0)
		{
			const auto *ret = addr->group->get_one();

			if (ret)
				addr = ret;
		}
		return addr;
	}

	inline bool is_alive_or_group_alive(const EndpointAddress *addr) const
	{
		return ((addr->params.group_id < 0 &&
					addr->fail_count < addr->params.max_fails) || 
				(addr->params.group_id >= 0 &&
					addr->group->nalives > 0));
	}
};

class UPSWeightedRandomPolicy : public UPSGroupPolicy
{
public:
	UPSWeightedRandomPolicy(bool try_another)
	{
		this->total_weight = 0;
		this->available_weight = 0;
		this->try_another = try_another;
	}
	const EndpointAddress *first_stradegy(const ParsedURI& uri);
	const EndpointAddress *another_stradegy(const ParsedURI& uri);

protected:
	int total_weight;
	int available_weight;

private:
	virtual void recover_one_server(const EndpointAddress *addr);
	virtual void fuse_one_server(const EndpointAddress *addr);
	virtual void add_server_locked(EndpointAddress *addr);
	virtual int remove_server_locked(const std::string& address);
};

class UPSConsistentHashPolicy : public UPSGroupPolicy
{
public:
	UPSConsistentHashPolicy()
	{
		this->consistent_hash = this->default_consistent_hash;
	}

	UPSConsistentHashPolicy(upstream_route_t consistent_hash)
	{
		this->consistent_hash = std::move(consistent_hash);
	}

protected:
	const EndpointAddress *first_stradegy(const ParsedURI& uri);

private:
	upstream_route_t consistent_hash;

public:
	static unsigned int default_consistent_hash(const char *path,
												const char *query,
												const char *fragment)
	{
	    static std::hash<std::string> std_hash;
	    std::string str(path);

    	str += query;
    	str += fragment;
    	return std_hash(str);
	}
};

class UPSManualPolicy : public UPSGroupPolicy
{
public:
	UPSManualPolicy(bool try_another, upstream_route_t select,
					upstream_route_t try_another_select)
	{
		this->try_another = try_another;
		this->manual_select = select;
		this->try_another_select = try_another_select;
	}
	
	const EndpointAddress *first_stradegy(const ParsedURI& uri);
	const EndpointAddress *another_stradegy(const ParsedURI& uri);

private:
	upstream_route_t manual_select;
	upstream_route_t try_another_select;
};

#endif


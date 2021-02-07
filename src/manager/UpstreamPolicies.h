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

#include <pthread.h>
#include <vector>
#include <atomic>
#include "URIParser.h"
#include "EndpointParams.h"
#include "WFNameService.h"
#include "WFDNSResolver.h"
#include "WFGlobal.h"
#include "WFTaskError.h"
#include "UpstreamManager.h"
#include "ServiceGovernance.h"

class EndpointGroup;
class UPSGroupPolicy;

class UPSAddress : public EndpointAddress
{
public:
	EndpointGroup *group;
	unsigned int consistent_hash[VIRTUAL_GROUP_SIZE];

public:
	UPSAddress(const std::string& address,
			   const struct AddressParams *address_params);
};

class EndpointGroup
{
public:
	int id;
	UPSGroupPolicy *policy;
	struct rb_node rb;
	pthread_mutex_t mutex;
	std::vector<UPSAddress *> mains;
	std::vector<UPSAddress *> backups;
	std::atomic<int> nalives;
	int weight;

	EndpointGroup(int group_id, UPSGroupPolicy *policy) :
			mutex(PTHREAD_MUTEX_INITIALIZER)
	{
		this->id = group_id;
		this->policy = policy;
		this->nalives = 0;
		this->weight = 0;
	}

public:
	const UPSAddress *get_one();
	const UPSAddress *get_one_backup();
};

class UPSGroupPolicy : public ServiceGovernance
{
public:
	UPSGroupPolicy();
	~UPSGroupPolicy();

protected:
	struct rb_root group_map;
	EndpointGroup *default_group;

private:
	virtual void recover_one_server(const UPSAddress *addr)
	{
		this->nalives++;
		addr->group->nalives++;
	}

	virtual void fuse_one_server(const UPSAddress *addr)
	{
		this->nalives--;
		addr->group->nalives--;
	}

	virtual bool select(const ParsedURI& uri, UPSAddress **addr);

protected:
	virtual void add_server_locked(UPSAddress *addr);
	virtual int remove_server_locked(const std::string& address);

	const UPSAddress *consistent_hash_with_group(unsigned int hash);
	const UPSAddress *check_and_get(const UPSAddress *addr, bool flag);

	inline bool is_alive_or_group_alive(const UPSAddress *addr) const
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
	const UPSAddress *first_stradegy(const ParsedURI& uri);
	const UPSAddress *another_stradegy(const ParsedURI& uri);

protected:
	int total_weight;
	int available_weight;

private:
	virtual void recover_one_server(const UPSAddress *addr);
	virtual void fuse_one_server(const UPSAddress *addr);
	virtual void add_server_locked(UPSAddress *addr);
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
	const UPSAddress *first_stradegy(const ParsedURI& uri);

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
	
	const UPSAddress *first_stradegy(const ParsedURI& uri);
	const UPSAddress *another_stradegy(const ParsedURI& uri);

private:
	upstream_route_t manual_select;
	upstream_route_t try_another_select;
};

#endif


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
#include "ServiceGovernance.h"

class EndpointGroup;
class UPSGroupPolicy;

class UPSAddrParams : public PolicyAddrParams
{
public:
	unsigned short weight;
	short server_type;
	int group_id;
	EndpointGroup *group;
	unsigned int consistent_hash[VIRTUAL_GROUP_SIZE];

	UPSAddrParams();
	UPSAddrParams(const struct AddressParams *params,
				  const std::string& address);
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

class UPSGroupPolicy : public ServiceGovernance
{
public:
	UPSGroupPolicy();
	~UPSGroupPolicy();

	virtual bool select(const ParsedURI& uri, EndpointAddress **addr);
	virtual void add_server(const std::string& address,
							const AddressParams *params);
	virtual int replace_server(const std::string& address,
							   const AddressParams *params);
	void get_main_address(std::vector<std::string>& addr_list);

protected:
	struct rb_root group_map;
	EndpointGroup *default_group;

private:
	virtual void recover_one_server(const EndpointAddress *addr)
	{
		this->nalives++;
		UPSAddrParams *params = static_cast<UPSAddrParams *>(addr->params);
		params->group->nalives++;
	}

	virtual void fuse_one_server(const EndpointAddress *addr)
	{
		this->nalives--;
		UPSAddrParams *params = static_cast<UPSAddrParams *>(addr->params);
		params->group->nalives--;
	}

protected:
	virtual void add_server_locked(EndpointAddress *addr);
	virtual int remove_server_locked(const std::string& address);

	const EndpointAddress *consistent_hash_with_group(unsigned int hash);
	const EndpointAddress *check_and_get(const EndpointAddress *addr, bool flag);

	inline bool is_alive_or_group_alive(const EndpointAddress *addr) const
	{
		UPSAddrParams *params = static_cast<UPSAddrParams *>(addr->params);
		return ((params->group_id < 0 &&
					addr->fail_count < addr->params->max_fails) ||
				(params->group_id >= 0 &&
					params->group->nalives > 0));
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


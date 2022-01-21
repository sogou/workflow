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

#ifndef _UPSTREAMPOLICIES_H_
#define _UPSTREAMPOLICIES_H_

#include <utility>
#include <vector>
#include <functional>
#include "URIParser.h"
#include "EndpointParams.h"
#include "WFNameService.h"
#include "WFServiceGovernance.h"

using upstream_route_t = std::function<unsigned int (const char *, const char *, const char *)>;

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

	UPSAddrParams(const struct AddressParams *params,
				  const std::string& address);
};

class UPSGroupPolicy : public WFServiceGovernance
{
public:
	UPSGroupPolicy();
	~UPSGroupPolicy();

	virtual bool select(const ParsedURI& uri, WFNSTracing *tracing,
						EndpointAddress **addr);
	virtual void add_server(const std::string& address,
							const struct AddressParams *params);
	virtual int replace_server(const std::string& address,
							   const struct AddressParams *params);
	void get_main_address(std::vector<std::string>& addr_list);

protected:
	struct rb_root group_map;
	EndpointGroup *default_group;

private:
	virtual void recover_one_server(const EndpointAddress *addr);
	virtual void fuse_one_server(const EndpointAddress *addr);

protected:
	virtual void add_server_locked(EndpointAddress *addr);
	virtual int remove_server_locked(const std::string& address);

	EndpointAddress *consistent_hash_with_group(unsigned int hash);
	EndpointAddress *check_and_get(EndpointAddress *addr,
								   bool flag, WFNSTracing *tracing);

	bool is_alive(const EndpointAddress *addr) const;
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
	EndpointAddress *first_strategy(const ParsedURI& uri,
									WFNSTracing *tracing);
	EndpointAddress *another_strategy(const ParsedURI& uri,
									  WFNSTracing *tracing);

protected:
	virtual void add_server_locked(EndpointAddress *addr);
	virtual int remove_server_locked(const std::string& address);
	int total_weight;
	int available_weight;

private:
	virtual void recover_one_server(const EndpointAddress *addr);
	virtual void fuse_one_server(const EndpointAddress *addr);
	static int select_history_weight(WFNSTracing *tracing);
};

class UPSVNSWRRPolicy : public UPSWeightedRandomPolicy
{
public:
	UPSVNSWRRPolicy() : UPSWeightedRandomPolicy(false)
	{
		this->cur_idx = 0;
		this->try_another = false;
	};
	EndpointAddress *first_strategy(const ParsedURI& uri,
									WFNSTracing *tracing);

private:
	virtual void add_server_locked(EndpointAddress *addr);
	virtual int remove_server_locked(const std::string& address);
	void init();
	void init_virtual_nodes();
	std::vector<size_t> pre_generated_vec;
	std::vector<int> current_weight_vec;
	size_t cur_idx;
};

class UPSConsistentHashPolicy : public UPSGroupPolicy
{
public:
	UPSConsistentHashPolicy(upstream_route_t consistent_hash) :
		consistent_hash(std::move(consistent_hash))
	{
	}

protected:
	EndpointAddress *first_strategy(const ParsedURI& uri,
									WFNSTracing *tracing);

private:
	upstream_route_t consistent_hash;
};

class UPSManualPolicy : public UPSGroupPolicy
{
public:
	UPSManualPolicy(bool try_another, upstream_route_t select,
					upstream_route_t try_another_select) :
		manual_select(std::move(select)),
		another_select(std::move(try_another_select))
	{
		this->try_another = try_another;
	}

	EndpointAddress *first_strategy(const ParsedURI& uri,
									WFNSTracing *tracing);
	EndpointAddress *another_strategy(const ParsedURI& uri,
									  WFNSTracing *tracing);

private:
	upstream_route_t manual_select;
	upstream_route_t another_select;
};

#endif

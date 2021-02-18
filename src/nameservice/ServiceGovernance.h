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
*/

#ifndef _SERVICE_GOVERNANCE_H_
#define _SERVICE_GOVERNANCE_H_ 

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

#define MTTR_SECOND_DEFAULT	30
#define VIRTUAL_GROUP_SIZE  16

#define GET_CURRENT_SECOND  std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count()

enum ServerChangeState
{
	ADD_SERVER		=	0,
	REMOVE_SERVER	=	1,
	RECOVER_SERVER	=	2,
	FUSE_SERVER		=	3,
};

class PolicyAddrParams
{
public:
	struct EndpointParams endpoint_params;
	unsigned int dns_ttl_default;
	unsigned int dns_ttl_min;
	unsigned int max_fails;

	PolicyAddrParams();
	PolicyAddrParams(const struct AddressParams *params);
};

class EndpointAddress
{
public:
	std::string address;
	std::string host;
	std::string port;
	std::atomic<unsigned int> fail_count;
	long long broken_timeout;
	PolicyAddrParams *params;

	struct address_entry
	{
		struct list_head list;
		EndpointAddress *ptr;
	} entry;

public:
	EndpointAddress(const std::string& address, PolicyAddrParams *params);
	virtual ~EndpointAddress() { delete this->params; }
};

class ServiceGovernance : public WFDNSResolver
{
public:
	virtual WFRouterTask *create_router_task(const struct WFNSParams *params,
											 router_callback_t callback);
	virtual void success(RouteManager::RouteResult *result, void *cookie,
					 	 CommTarget *target);
	virtual void failed(RouteManager::RouteResult *result, void *cookie,
						CommTarget *target);

	virtual void add_server(const std::string& address,
							const AddressParams *params);
	int remove_server(const std::string& address);
	virtual int replace_server(const std::string& address,
							   const AddressParams *params);

	void enable_server(const std::string& address);
	void disable_server(const std::string& address);
	virtual void get_current_address(std::vector<std::string>& addr_list);
	virtual void server_list_change(const EndpointAddress *address, int state)
	{}
	void set_mttr_second(unsigned int second) { this->mttr_second = second; }

public:
	ServiceGovernance()
	{
		this->nalives = 0;
		this->try_another = false;
		this->mttr_second = MTTR_SECOND_DEFAULT;
		INIT_LIST_HEAD(&this->breaker_list);
	}

	virtual ~ServiceGovernance()
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
	unsigned int mttr_second;

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

#endif


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

#include <pthread.h>
#include <unordered_map>
#include <vector>
#include <atomic>
#include "URIParser.h"
#include "EndpointParams.h"
#include "WFNameService.h"
#include "WFDNSResolver.h"
#include "WFGlobal.h"
#include "WFTaskError.h"
#include "UpstreamManager.h"

#define MTTR_SECOND			30
#define VIRTUAL_GROUP_SIZE  16

#define GET_CURRENT_SECOND  std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count()

class EndpointAddress
{
public:
	AddressParams params;
	std::string address;
	std::string host;
	std::string port;
	short port_value; //TODO
	struct list_head list;
	std::atomic<unsigned int> fail_count;
	long long broken_timeout;

public:
	EndpointAddress(const std::string& address,
					const struct AddressParams *address_params);
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

	void add_server(const std::string& address, const AddressParams *address_params);
	int remove_server(const std::string& address);
	int replace_server(const std::string& address, const AddressParams *address_params);

	virtual void enable_server(const std::string& address);
	virtual void disable_server(const std::string& address);
	virtual void get_main_address(std::vector<std::string>& addr_list);
	// virtual void server_list_change(/* std::vector<server> status */) {}

public:
	ServiceGovernance() :
		breaker_lock(PTHREAD_MUTEX_INITIALIZER),
		rwlock(PTHREAD_RWLOCK_INITIALIZER)
	{
		this->nalives = 0;
		this->try_another = false;
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
	pthread_mutex_t breaker_lock;

protected:
	virtual const EndpointAddress *first_stradegy(const ParsedURI& uri);
	virtual const EndpointAddress *another_stradegy(const ParsedURI& uri);
	void check_breaker();

	std::vector<EndpointAddress *> servers; // current servers
	std::vector<EndpointAddress *> addresses; // memory management
	std::unordered_map<std::string,
					   std::vector<EndpointAddress *>> server_map;
	pthread_rwlock_t rwlock;
	std::atomic<int> nalives;
	bool try_another;
};

#endif


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
           Xie Han (xiehan@sogou-inc.com)
*/

#ifndef _WFSERVICEGOVERNANCE_H_
#define _WFSERVICEGOVERNANCE_H_

#include <stdint.h>
#include <pthread.h>
#include <unordered_map>
#include <vector>
#include <atomic>
#include <functional>
#include "URIParser.h"
#include "EndpointParams.h"
#include "WFNameService.h"

#define MTTR_SECOND_DEFAULT 30
#define VIRTUAL_GROUP_SIZE  16

struct AddressParams
{
	struct EndpointParams endpoint_params; ///< Connection config
	unsigned int dns_ttl_default;          ///< in seconds, DNS TTL when network request success
	unsigned int dns_ttl_min;              ///< in seconds, DNS TTL when network request fail
/**
 * - The max_fails directive sets the number of consecutive unsuccessful attempts to communicate with the server.
 * - After 30s following the server failure, upstream probe the server with some live client`s requests.
 * - If the probes have been successful, the server is marked as a live one.
 * - If max_fails is set to 1, it means server would out of upstream selection in 30 seconds when failed only once
 */
	unsigned int max_fails;                ///< [1, INT32_MAX] max_fails = 0 means max_fails = 1
	unsigned short weight;                 ///< [1, 65535] weight = 0 means weight = 1. only for main server
	int server_type;                       ///< 0 for main and 1 for backup
	int group_id;                          ///< -1 means no group. Backup without group will be backup for any main
};

static constexpr struct AddressParams ADDRESS_PARAMS_DEFAULT =
{
	.endpoint_params	=	ENDPOINT_PARAMS_DEFAULT,
	.dns_ttl_default	=	12 * 3600,
	.dns_ttl_min		=	180,
	.max_fails			=	200,
	.weight				=	1,
	.server_type		=	0,	/* 0 for main and 1 for backup. */
	.group_id			=	-1,
};

class PolicyAddrParams
{
public:
	struct EndpointParams endpoint_params;
	unsigned int dns_ttl_default;
	unsigned int dns_ttl_min;
	unsigned int max_fails;

public:
	PolicyAddrParams();
	PolicyAddrParams(const struct AddressParams *params);
	virtual ~PolicyAddrParams() { }
};

class EndpointAddress
{
public:
	std::string address;
	std::string host;
	std::string port;
	unsigned int fail_count;
	std::atomic<int> ref;
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

class WFServiceGovernance : public WFNSPolicy
{
public:
	virtual WFRouterTask *create_router_task(const struct WFNSParams *params,
											 router_callback_t callback);
	virtual void success(RouteManager::RouteResult *result,
						 WFNSTracing *tracing,
					 	 CommTarget *target);
	virtual void failed(RouteManager::RouteResult *result,
						WFNSTracing *tracing,
						CommTarget *target);

	virtual void add_server(const std::string& address,
							const struct AddressParams *params);
	int remove_server(const std::string& address);
	virtual int replace_server(const std::string& address,
							   const struct AddressParams *params);

	void enable_server(const std::string& address);
	void disable_server(const std::string& address);
	virtual void get_current_address(std::vector<std::string>& addr_list);

	void set_mttr_second(unsigned int second) { this->mttr_second = second; }
	static bool in_select_history(WFNSTracing *tracing, EndpointAddress *addr);

public:
	using pre_select_t = std::function<WFConditional *(WFRouterTask *)>;

	void set_pre_select(pre_select_t pre_select)
	{
		pre_select_ = std::move(pre_select);
	}

public:
	WFServiceGovernance() :
		breaker_lock(PTHREAD_MUTEX_INITIALIZER),
		rwlock(PTHREAD_RWLOCK_INITIALIZER)
	{
		this->nalives = 0;
		this->try_another = false;
		this->mttr_second = MTTR_SECOND_DEFAULT;
		INIT_LIST_HEAD(&this->breaker_list);
	}

	virtual ~WFServiceGovernance()
	{
		for (EndpointAddress *addr : this->servers)
			delete addr;
	}

private:
	virtual bool select(const ParsedURI& uri, WFNSTracing *tracing,
						EndpointAddress **addr);

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
	void check_breaker_locked(int64_t cur_time);

private:
	struct list_head breaker_list;
	pthread_mutex_t breaker_lock;
	unsigned int mttr_second;
	pre_select_t pre_select_;

protected:
	virtual EndpointAddress *first_strategy(const ParsedURI& uri,
											WFNSTracing *tracing);
	virtual EndpointAddress *another_strategy(const ParsedURI& uri,
											  WFNSTracing *tracing);
	void check_breaker();
	void try_clear_breaker();
	void pre_delete_server(EndpointAddress *addr);

	struct TracingData
	{
		std::vector<EndpointAddress *> history;
		WFServiceGovernance *sg;
	};

	static void tracing_deleter(void *data);

	std::vector<EndpointAddress *> servers;
	std::unordered_map<std::string,
					   std::vector<EndpointAddress *>> server_map;
	pthread_rwlock_t rwlock;
	std::atomic<int> nalives;
	bool try_another;
	friend class WFSGResolverTask;
};

#endif


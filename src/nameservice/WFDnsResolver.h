/*
  Copyright (c) 2020 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Xie Han (xiehan@sogou-inc.com)
*/

#ifndef _WFDNSRESOLVER_H_
#define _WFDNSRESOLVER_H_

#include <string>
#include <functional>
#include "Workflow.h"
#include "DnsMessage.h"
#include "DnsRoutine.h"
#include "EndpointParams.h"
#include "WFNameService.h"

class WFResolverTask : public WFRouterTask
{
public:
	WFResolverTask(const struct WFNSParams *ns_params,
				   unsigned int dns_ttl_default, unsigned int dns_ttl_min,
				   const struct EndpointParams *ep_params,
				   router_callback_t&& cb) :
		WFRouterTask(std::move(cb)),
		ns_params_(*ns_params),
		ep_params_(*ep_params)
	{
		dns_ttl_default_ = dns_ttl_default;
		dns_ttl_min_ = dns_ttl_min;
	}

	WFResolverTask(const struct WFNSParams *ns_params,
				   router_callback_t&& cb) :
		WFRouterTask(std::move(cb)),
		ns_params_(*ns_params)
	{
	}

protected:
	virtual void dispatch();
	virtual SubTask *done();

private:
	using DnsTask_thrd = WFThreadTask<DnsInput, DnsOutput>;
	using DnsTask_net = WFNetworkTask<protocol::DnsRequest,
									  protocol::DnsResponse>;
	void thread_dns_callback(DnsTask_thrd *dns_task);
	void dns_single_callback(DnsTask_net *dns_task);
	static void dns_partial_callback(DnsTask_net *dns_task);
	void dns_parallel_callback(const ParallelWork *pwork);
	void dns_callback_internal(DnsOutput *dns_task,
							   unsigned int ttl_default,
							   unsigned int ttl_min);

protected:
	struct WFNSParams ns_params_;
	unsigned int dns_ttl_default_;
	unsigned int dns_ttl_min_;
	struct EndpointParams ep_params_;
	bool query_dns_;

private:
	unsigned short port_;
	const char *host_;
};

class WFDnsResolver : public WFNSPolicy
{
public:
	virtual WFRouterTask *create_router_task(const struct WFNSParams *params,
											 router_callback_t callback);
};

#endif


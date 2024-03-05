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

  Authors: Liu Kai (liukaidx@sogou-inc.com)
*/

#ifndef _WFDNSSERVER_H_
#define _WFDNSSERVER_H_

#include "DnsMessage.h"
#include "WFServer.h"
#include "WFTaskFactory.h"

using dns_process_t = std::function<void (WFDnsTask *)>;
using WFDnsServer = WFServer<protocol::DnsRequest,
							 protocol::DnsResponse>;

static constexpr struct WFServerParams DNS_SERVER_PARAMS_DEFAULT =
{
	.transport_type			=	TT_UDP,
	.max_connections		=	2000,
	.peer_response_timeout	=	10 * 1000,
	.receive_timeout		=	-1,
	.keep_alive_timeout		=	300 * 1000,
	.request_size_limit		=	(size_t)-1,
	.ssl_accept_timeout		=	5000,
};

template<> inline
WFDnsServer::WFServer(dns_process_t proc) :
	WFServerBase(&DNS_SERVER_PARAMS_DEFAULT),
	process(std::move(proc))
{
}

template<> inline
CommSession *WFDnsServer::new_session(long long seq, CommConnection *conn)
{
	WFDnsTask *task;

	task = WFServerTaskFactory::create_dns_task(this, this->process);
	task->set_keep_alive(this->params.keep_alive_timeout);
	task->set_receive_timeout(this->params.receive_timeout);
	task->get_req()->set_size_limit(this->params.request_size_limit);

	return task;
}

#endif


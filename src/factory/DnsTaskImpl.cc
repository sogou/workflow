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

  Author: Liu Kai (liukaidx@sogou-inc.com)
*/

#include <string>
#include "WFTaskError.h"
#include "WFTaskFactory.h"
#include "DnsMessage.h"

using namespace protocol;

#define DNS_KEEPALIVE_DEFAULT	(60 * 1000)

/**********Client**********/

class ComplexDnsTask : public WFComplexClientTask<DnsRequest, DnsResponse,
							  std::function<void (WFDnsTask *)>>
{
	static struct addrinfo hints;

public:
	ComplexDnsTask(int retry_max, dns_callback_t&& cb):
		WFComplexClientTask(retry_max, std::move(cb))
	{
		this->set_transport_type(TT_UDP);
	}

protected:
	virtual CommMessageOut *message_out();
	virtual bool init_success();
	virtual bool finish_once();

private:
	bool need_redirect();
};

struct addrinfo ComplexDnsTask::hints =
{
	.ai_flags     = AI_NUMERICSERV | AI_NUMERICHOST,
	.ai_family    = AF_UNSPEC,
	.ai_socktype  = SOCK_STREAM
};

CommMessageOut *ComplexDnsTask::message_out()
{
	DnsRequest *req = this->get_req();
	DnsResponse *resp = this->get_resp();
	TransportType type = this->get_transport_type();

	if (req->get_id() == 0)
		req->set_id((this->get_seq() + 1) * 99991 % 65535 + 1);
	resp->set_request_id(req->get_id());
	resp->set_request_name(req->get_question_name());
	req->set_single_packet(type == TT_UDP);
	resp->set_single_packet(type == TT_UDP);

	return this->WFClientTask::message_out();
}

bool ComplexDnsTask::init_success()
{
	if (uri_.scheme && strcasecmp(uri_.scheme, "dnss") == 0)
		this->WFComplexClientTask::set_transport_type(TT_TCP_SSL);
	else if (!uri_.scheme || strcasecmp(uri_.scheme, "dns") != 0)
	{
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_URI_SCHEME_INVALID;
		return false;
	}

	if (!this->route_result_.request_object)
	{
		TransportType type = this->get_transport_type();
		struct addrinfo *addr;
		int ret;

		ret = getaddrinfo(uri_.host, uri_.port, &hints, &addr);
		if (ret != 0)
		{
			this->state = WFT_STATE_TASK_ERROR;
			this->error = WFT_ERR_URI_PARSE_FAILED;
			return false;
		}

		auto *ep = &WFGlobal::get_global_settings()->dns_server_params;
		ret = WFGlobal::get_route_manager()->get(type, addr, info_, ep,
												 uri_.host, route_result_);
		freeaddrinfo(addr);
		if (ret < 0)
		{
			this->state = WFT_STATE_SYS_ERROR;
			this->error = errno;
			return false;
		}
	}

	return true;
}

bool ComplexDnsTask::finish_once()
{
	if (this->state == WFT_STATE_SUCCESS)
	{
		if (need_redirect())
			this->set_redirect(uri_);
		else if (this->state != WFT_STATE_SUCCESS)
			this->disable_retry();
	}

	/* If retry times meet retry max and there is no redirect,
	 * we ask the client for a retry or redirect.
	 */
	if (retry_times_ == retry_max_ && !redirect_ && *this->get_mutable_ctx())
	{
		/* Reset type to UDP before a client redirect. */
		this->set_transport_type(TT_UDP);
		(*this->get_mutable_ctx())(this);
	}

	return true;
}

bool ComplexDnsTask::need_redirect()
{
	DnsResponse *client_resp = this->get_resp();
	TransportType type = this->get_transport_type();

	if (type == TT_UDP && client_resp->get_tc() == 1)
	{
		this->set_transport_type(TT_TCP);
		return true;
	}

	return false;
}

/**********Client Factory**********/

WFDnsTask *WFTaskFactory::create_dns_task(const std::string& url,
										  int retry_max,
										  dns_callback_t callback)
{
	ParsedURI uri;

	URIParser::parse(url, uri);
	return WFTaskFactory::create_dns_task(uri, retry_max, std::move(callback));
}

WFDnsTask *WFTaskFactory::create_dns_task(const ParsedURI& uri,
										  int retry_max,
										  dns_callback_t callback)
{
	ComplexDnsTask *task = new ComplexDnsTask(retry_max, std::move(callback));
	const char *name;

	if (uri.path && uri.path[0] && uri.path[1])
		name = uri.path + 1;
	else
		name = ".";

	DnsRequest *req = task->get_req();
	req->set_question(name, DNS_TYPE_A, DNS_CLASS_IN);

	task->init(uri);
	task->set_keep_alive(DNS_KEEPALIVE_DEFAULT);
	return task;
}


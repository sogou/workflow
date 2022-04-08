/*
  Copyright (c) 2022 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Authors: Wang Zhenpeng (wangzhenpeng@sogou-inc.com)
*/

#ifndef _WFCONSULCLIENT_H_
#define _WFCONSULCLIENT_H_

#include <string>
#include <vector>
#include <utility>
#include <functional>
#include "HttpMessage.h"
#include "WFTaskFactory.h"
#include "ConsulDataTypes.h"

class WFConsulTask;
using consul_callback_t = std::function<void (WFConsulTask *)>;

enum
{
	CONSUL_API_TYPE_UNKNOWN = 0,
	CONSUL_API_TYPE_DISCOVER,
	CONSUL_API_TYPE_LIST_SERVICE,
	CONSUL_API_TYPE_REGISTER,
	CONSUL_API_TYPE_DEREGISTER,
};

class WFConsulTask : public WFGenericTask
{
public:
	bool get_discover_result(
			std::vector<struct protocol::ConsulServiceInstance>& result);

	bool get_list_service_result(
			std::vector<struct protocol::ConsulServiceTags>& result);

public:
	void set_service(const struct protocol::ConsulService *service);

	void set_api_type(int api_type)
	{
		this->api_type = api_type;
	}

	int get_api_type() const
	{
		return this->api_type;
	}

	void set_callback(consul_callback_t cb)
	{
		this->callback = std::move(cb);
	}

	void set_consul_index(long long consul_index)
	{
		this->consul_index = consul_index;
	}
	long long get_consul_index() const { return this->consul_index; }

	const protocol::HttpResponse *get_http_resp() const
	{
		return &this->http_resp;
	}

protected:
	void set_config(protocol::ConsulConfig conf)
	{
		this->config = std::move(conf);
	}

protected:
	virtual void dispatch();
	virtual SubTask *done();

	WFHttpTask *create_discover_task();
	WFHttpTask *create_list_service_task();
	WFHttpTask *create_register_task();
	WFHttpTask *create_deregister_task();

	std::string generate_discover_request();
	long long get_consul_index(protocol::HttpResponse *resp);

	static bool check_task_result(WFHttpTask *task, WFConsulTask *consul_task);
	static void discover_callback(WFHttpTask *task);
	static void list_service_callback(WFHttpTask *task);
	static void register_callback(WFHttpTask *task);

protected:
	protocol::ConsulConfig config;
	struct protocol::ConsulService service;
	std::string proxy_url;
	int retry_max;
	int api_type;
	bool finish;
	long long consul_index;
	protocol::HttpResponse http_resp;
	consul_callback_t callback;

protected:
	WFConsulTask(const std::string& proxy_url,
				 const std::string& service_namespace,
				 const std::string& service_name,
				 const std::string& service_id,
				 int retry_max, consul_callback_t&& cb);
	virtual ~WFConsulTask() { }
	friend class WFConsulClient;
};

class WFConsulClient
{
public:
	// example: http://127.0.0.1:8500
	int init(const std::string& proxy_url);
	int init(const std::string& proxy_url, protocol::ConsulConfig config);
	void deinit() { }

	WFConsulTask *create_discover_task(const std::string& service_namespace,
									   const std::string& service_name,
									   int retry_max,
									   consul_callback_t cb);

	WFConsulTask *create_list_service_task(const std::string& service_namespace,
										   int retry_max,
										   consul_callback_t cb);

	WFConsulTask *create_register_task(const std::string& service_namespace,
									   const std::string& service_name,
									   const std::string& service_id,
									   int retry_max,
									   consul_callback_t cb);

	WFConsulTask *create_deregister_task(const std::string& service_namespace,
										 const std::string& service_id,
										 int retry_max,
										 consul_callback_t cb);

private:
	std::string proxy_url;
	protocol::ConsulConfig config;

public:
	virtual ~WFConsulClient() { }
};

#endif


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

  Author: Wang Zhenpeng (wangzhenpeng@sogou-inc.com)
*/

#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <iostream>
#include "workflow/WFConsulClient.h"
#include "workflow/ConsulDataTypes.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/WFFacilities.h"
#include "workflow/HttpMessage.h"
#include "workflow/WFGlobal.h"

using namespace protocol;

static WFFacilities::WaitGroup wait_group(1);

std::string url;
WFConsulClient client;

void print_discover_result(std::vector<struct protocol::ConsulServiceInstance>& discover_result)
{
	for (const auto& instance : discover_result)
	{
		fprintf(stderr, "%s", "discover_instance\n");
		
		fprintf(stderr, "node_id:%s\n", instance.node_id.c_str());
		fprintf(stderr, "node_name:%s\n", instance.node_name.c_str());
		fprintf(stderr, "node_address:%s\n", instance.node_address.c_str());
		fprintf(stderr, "dc:%s\n", instance.dc.c_str());
		const std::map<std::string, std::string>& node_meta = instance.node_meta;
		for (const auto& meta_kv : node_meta)
		{
			fprintf(stderr, "node_meta:%s = %s\n", meta_kv.first.c_str(),
												   meta_kv.second.c_str());
		}
		fprintf(stderr, "create_index:%lld\n", instance.create_index);
		fprintf(stderr, "modify_index:%lld\n", instance.modify_index);

		fprintf(stderr, "service_id:%s\n", instance.service.service_id.c_str());
		fprintf(stderr, "service_name:%s\n", instance.service.service_name.c_str());
		fprintf(stderr, "service_namespace:%s\n", instance.service.service_namespace.c_str());
		fprintf(stderr, "service_address:%s\n", instance.service.service_address.first.c_str());
		fprintf(stderr, "service_port:%d\n", instance.service.service_address.second);
		fprintf(stderr, "service_tag_override:%d\n", instance.service.tag_override);
		fprintf(stderr, "%s", "service_tags:");
		const std::vector<std::string>& tags = instance.service.tags;
		for (const auto& tag : tags)
		{
			fprintf(stderr, "%s,", tag.c_str()); 
		}
		fprintf(stderr, "\n");
		const std::map<std::string, std::string>& service_meta = instance.service.meta;
		for (const auto& meta_kv : service_meta)
		{
			fprintf(stderr, "service_meta:%s = %s\n", meta_kv.first.c_str(),
													  meta_kv.second.c_str());
		}
		fprintf(stderr, "lan:%s:%d\n", instance.service.lan.first.c_str(),
									   instance.service.lan.second);
		fprintf(stderr, "lan_ipv4:%s:%d\n",
									instance.service.lan_ipv4.first.c_str(),
									instance.service.lan_ipv4.second);
		fprintf(stderr, "lan_ipv6:%s:%d\n",
									instance.service.lan_ipv6.first.c_str(),
									instance.service.lan_ipv6.second);
		fprintf(stderr, "wan:%s:%d\n", instance.service.wan.first.c_str(),
									   instance.service.wan.second);
		fprintf(stderr, "wan_ipv4:%s:%d\n",
									instance.service.wan_ipv4.first.c_str(),
									instance.service.wan_ipv4.second);
		fprintf(stderr, "wan_ipv6:%s:%d\n",
									instance.service.wan_ipv6.first.c_str(),
									instance.service.wan_ipv6.second);
		
		fprintf(stderr, "check_id:%s\n", instance.check_id.c_str());
		fprintf(stderr, "check_name:%s\n", instance.check_name.c_str());
		fprintf(stderr, "check_notes:%s\n", instance.check_notes.c_str());
		fprintf(stderr, "check_output:%s\n", instance.check_output.c_str());
		fprintf(stderr, "check_status:%s\n", instance.check_status.c_str());
		fprintf(stderr, "check_type:%s\n", instance.check_type.c_str());	
	}
}

void print_list_service_result(
	std::vector<struct protocol::ConsulServiceTags>& list_service_result)
{
	for (const auto& instance : list_service_result)
	{
		fprintf(stderr, "service name:%s tags:", instance.service_name.c_str());
		std::string tags_log;
		for (const auto& tag : instance.tags)
		{
			tags_log += tag;
			tags_log += ",";
		}
		if (tags_log.size() > 0)
			tags_log.pop_back();

		fprintf(stderr, "%s\n", tags_log.c_str());
	}
}

void consul_callback(WFConsulTask *task)
{
	int state = task->get_state();
	int error = task->get_error();

	if (state != WFT_STATE_SUCCESS)
	{
		fprintf(stderr, "error:%d, error msg:%s\n",
				 error, WFGlobal::get_error_string(state, error));
		fprintf(stderr, "Failed. Press Ctrl-C to exit.\n");
		wait_group.done();
		return;
	}

	int api_type = task->get_api_type();
	std::vector<struct protocol::ConsulServiceInstance> dis_result;
	std::vector<struct protocol::ConsulServiceTags> list_service_result;
	
	switch (api_type)
	{
	case CONSUL_API_TYPE_DISCOVER:
		fprintf(stderr, "discover ok\n");
		fprintf(stderr, "consul-index:%lld\n", task->get_consul_index());
		if (task->get_discover_result(dis_result))
			print_discover_result(dis_result);
		else
			fprintf(stderr, "error:%d\n", task->get_error());
		break;

	case CONSUL_API_TYPE_LIST_SERVICE:
		fprintf(stderr, "list service ok\n");
		if (task->get_list_service_result(list_service_result))
			print_list_service_result(list_service_result);
		else
			fprintf(stderr, "error:%d\n", task->get_error());
		break;

	case CONSUL_API_TYPE_REGISTER:
		fprintf(stderr, "register ok\n");
		break;

	case CONSUL_API_TYPE_DEREGISTER:
		fprintf(stderr, "deregister ok\n");
		break;

	default:
		break;
	}
	wait_group.done();
}

void sig_handler(int signo) { }

int main(int argc, char *argv[])
{
	if (argc < 3)
	{
		fprintf(stderr, "USAGE: %s url type(discover/register/deregister)<p/c> \n", argv[0]);
		exit(1);
	}

	signal(SIGINT, sig_handler);

	url = argv[1];
	if (strncmp(argv[1], "http://", 7) != 0)
		url = "http://" + url;

	ConsulConfig config;
	config.set_token("cd125427-3fd1-f326-bf46-fbce06cc9003");
	config.set_health_check(true);

	// http health check
	config.set_check_http_url("http://127.0.0.1:8000/health_check/sd");
	// config.add_http_header("Accept", {"text/html", "application/xml"});

	// tcp health check
	//config.set_check_tcp("127.0.0.1:80");

	client.init(url, config);

	WFConsulTask *task;

	if (0 == strcmp(argv[2], "discover"))
	{	
		task = client.create_discover_task("", "dev-wf_test_service_1", 3, consul_callback);
		config.set_blocking_query(true);
	}
	else if (0 == strcmp(argv[2], "list_service"))
	{
		task = client.create_list_service_task("", 3, consul_callback);
	}
	else if (0 == strcmp(argv[2], "register"))
	{
		task = client.create_register_task("", "dev-wf_test_service_1", "wf_test_service_id_2", 3, consul_callback);
		protocol::ConsulService service;
		service.tags.emplace_back("tag1");
		service.tags.emplace_back("tag2");
		service.service_address.first = "127.0.0.1";
		service.service_address.second = 8000;
		service.meta["mk1"] = "mv1";
		service.meta["mk2"] = "mv2";
		service.tag_override = true;
		task->set_service(&service);
	}
	else if (0 == strcmp(argv[2], "deregister"))
	{
		task = client.create_deregister_task("", "wf_test_service_id_2", 3, consul_callback);
	}
	else
	{
		fprintf(stderr, "USAGE: %s url <p/c> [compress_type/d]\n", argv[0]);
		exit(1);
	}

	task->start();

	wait_group.wait();

	return 0;
}

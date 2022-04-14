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

  Author: Wang Zhenpeng (wangzhenpeng@sogou-inc.com)
*/

#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>

#include "workflow/WFTaskFactory.h"
#include "workflow/WFFacilities.h"
#include "workflow/HttpMessage.h"
#include "workflow/WFHttpServer.h"
#include "workflow/WFConsulManager.h"
#include "workflow/ConsulDataTypes.h"

using namespace protocol;

void print_services_result(std::vector<std::string>& services)
{
	fprintf(stderr, "watching services:");
	for (const auto& service : services)
	{
		fprintf(stderr, "%s,", service.c_str());
	}
	fprintf(stderr, "\n");
}

void sig_handler(int signo) { }

int main(int argc, char *argv[])
{
	if (argc < 6)
	{
		fprintf(stderr, "USAGE: %s url api_type(register or watch) service_name address port <p/c> \n", argv[0]);
		exit(1);
	}

	signal(SIGINT, sig_handler);

	std::string url = argv[1];
	if (strncmp(argv[1], "http://", 7) != 0)
		url = "http://" + url;

	std::string api_type = argv[2];
	std::string service_namespace = "";
	std::string service_name = argv[3];

	ConsulConfig config;
	config.set_token("cd125427-3fd1-f326-bf46-fbce06cc9003");

	if (api_type == "register")
	{
		WFFacilities::WaitGroup wait_group(1);
		std::string address = argv[4];
		unsigned short port = atoi(argv[5]);

		config.set_health_check(true);
		// http health check
		config.set_check_http_url("http://" + address + ":" + std::to_string(port));

		WFConsulManager cm;
		if (cm.init(url, config) != 0)
		{
			fprintf(stderr, "init failed\n");
			exit(1);
		}

		std::string service_id = service_namespace + "." + service_name;
		service_id += address;
		service_id += std::to_string(port);
		WFHttpServer server([port](WFHttpTask *task)
		{
			task->get_resp()->append_output_body(
				"Response from instance 127.0.0.1:" + std::to_string(port));
		});

		if (server.start(port) != 0)
		{
			fprintf(stderr, "start server error\n");
			exit(1);
		}

		struct protocol::ConsulService service;
		service.service_namespace = service_namespace;
		service.service_name = service_name;
		service.service_id = service_id;
		service.tags.emplace_back("v1");
		service.meta["k1"] = "v1";
		service.meta["k2"] = "v2";
		service.service_address.first = address;
		service.service_address.second = port;
		service.tag_override = true;
		if (cm.register_service(&service) != 0)
		{
			fprintf(stderr, "register service failed\n");
			exit(1);
		}
		fprintf(stderr, "register service ok\n");
		wait_group.wait();
	}	
	else
	{
		config.set_passing(true);
		config.set_blocking_query(true);
		WFConsulManager cm;
		if (cm.init(url, config) != 0)
		{
			fprintf(stderr, "init failed\n");
			exit(1);
		}

		struct AddressParams address_params;
		address_params.endpoint_params.connect_timeout = 100;
		address_params.endpoint_params.response_timeout = 200;

		if (cm.watch_service(service_namespace, service_name, &address_params) != 0)
		{
			fprintf(stderr, "watch service failed\n");
			exit(1);
		}

		fprintf(stderr, "watch service ok\n");
		
		std::vector<std::string> services;
		cm.get_watching_services(services);
		print_services_result(services);		

		const int times = 200;
		WFFacilities::WaitGroup wait_group(times);
		auto cb = [&wait_group](WFHttpTask *task) {
			const void *body;
			size_t body_len;
			std::string str_body;
			if (task->get_resp()->get_parsed_body(&body, &body_len))
				str_body.assign((char *)body, body_len);

			fprintf(stderr, "Query callback. state = %d error = %d, body:%s\n",
					task->get_state(), task->get_error(), str_body.c_str());
			wait_group.done();
		};

		std::string request_url = "http://";
		request_url += service_namespace;
		request_url += ".";
		request_url += service_name;
		request_url += ":8080"; // port can be any

		for (int i = 0; i < times; ++i)
		{
			WFHttpTask *task = WFTaskFactory::create_http_task(request_url,
														   3, /* REDIRECT_MAX */
														   5, /* RETRY_MAX */
														   cb);
			task->start();
		}
		wait_group.wait();

		if (cm.unwatch_service(service_namespace, service_name) != 0)
		{
			fprintf(stderr, "unwatch service failed\n");
			exit(1);
		}
		fprintf(stderr, "unwatch service ok\n");
	}

	return 0;
}

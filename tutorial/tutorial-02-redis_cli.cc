/*
  Copyright (c) 2019 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

	  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Xie Han (xiehan@sogou-inc.com;63350856@qq.com)
*/

#include <netdb.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "workflow/RedisMessage.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/WFFacilities.h"

#define RETRY_MAX       2

struct tutorial_task_data
{
	std::string url;
	std::string key;
};

void redis_callback(WFRedisTask *task)
{
	protocol::RedisRequest *req = task->get_req();
	protocol::RedisResponse *resp = task->get_resp();
	int state = task->get_state();
	int error = task->get_error();
	protocol::RedisValue val;

	switch (state)
	{
	case WFT_STATE_SYS_ERROR:
		fprintf(stderr, "system error: %s\n", strerror(error));
		break;
	case WFT_STATE_DNS_ERROR:
		fprintf(stderr, "DNS error: %s\n", gai_strerror(error));
		break;
	case WFT_STATE_SSL_ERROR:
		fprintf(stderr, "SSL error: %d\n", error);
		break;
	case WFT_STATE_TASK_ERROR:
		fprintf(stderr, "Task error: %d\n", error);
		break;
	case WFT_STATE_SUCCESS:
		resp->get_result(val);
		if (val.is_error())
		{
			fprintf(stderr, "%*s\n", (int)val.string_view()->size(),
									val.string_view()->c_str());
			state = WFT_STATE_TASK_ERROR;
		}
		break;
	}

	if (state != WFT_STATE_SUCCESS)
	{
		fprintf(stderr, "Failed. Press Ctrl-C to exit.\n");
		return;
	}

	std::string cmd;
	req->get_command(cmd);
	if (cmd == "SET")
	{
		tutorial_task_data *data = (tutorial_task_data *)task->user_data;
		WFRedisTask *next = WFTaskFactory::create_redis_task(data->url,
															 RETRY_MAX,
															 redis_callback);

		next->get_req()->set_request("GET", { data->key });
		/* Push next task(GET task) to current series. */
		series_of(task)->push_back(next);
		fprintf(stderr, "Redis SET request success. Trying to GET...\n");
	}
	else /* if (cmd == "GET") */
	{
		if (val.is_string())
		{
			fprintf(stderr, "Redis GET success. value = %s\n",
					val.string_value().c_str());
		}
		else
		{
			fprintf(stderr, "Error: Not a string value. \n");
		}

		fprintf(stderr, "Finished. Press Ctrl-C to exit.\n");
	}
}

static WFFacilities::WaitGroup wait_group(1);

void sig_handler(int signo)
{
	wait_group.done();
}

int main(int argc, char *argv[])
{
	WFRedisTask *task;

	if (argc != 4)
	{
		fprintf(stderr, "USAGE: %s <redis URL> <key> <value>\n", argv[0]);
		exit(1);
	}

	signal(SIGINT, sig_handler);

	/* This struct only used in this tutorial. */
	struct tutorial_task_data data;

	/* Redis URL format: redis://:password@host:port/dbnum
	   examples:
	   redis://127.0.0.1
	   redis://:12345@redis.sogou:6379/3
	*/
	data.url = argv[1];
	if (strncasecmp(argv[1], "redis://", 8) != 0 &&
		strncasecmp(argv[1], "rediss://", 9) != 0)
	{
		data.url = "redis://" + data.url;
	}

	data.key = argv[2];

	task = WFTaskFactory::create_redis_task(data.url, RETRY_MAX,
											redis_callback);
	protocol::RedisRequest *req = task->get_req();
	req->set_request("SET", { data.key, argv[3] });

	/* task->user_data is a public (void *), can store anything. */
	task->user_data = &data;

	/* task->start() equel to:
	 * Workflow::start_series_work(task, nullptr) or
	 * Workflow::create_series_work(task, nullptr)->start() */
	task->start();

	wait_group.wait();
	return 0;
}


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

/* Tuturial-03. Store wget result in redis: key=URL, value=Http Body*/
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "workflow/HttpMessage.h"
#include "workflow/HttpUtil.h"
#include "workflow/RedisMessage.h"
#include "workflow/Workflow.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/WFFacilities.h"

using namespace protocol;

#define REDIRECT_MAX    5
#define RETRY_MAX       2

struct tutorial_series_context
{
	std::string http_url;
	std::string redis_url;
	size_t body_len;
	bool success;
};

void redis_callback(WFRedisTask *task)
{
	int state = task->get_state();
	tutorial_series_context *context =
		(tutorial_series_context *)series_of(task)->get_context();
	RedisValue value;

	if (state == WFT_STATE_SUCCESS)
	{
		task->get_resp()->get_result(value);
		if (!value.is_error())
		{
			fprintf(stderr, "redis SET success: key: %s, value size: %zu\n",
							context->http_url.c_str(), context->body_len);
			context->success = true;
		}
		else
			fprintf(stderr, "redis error reply! Need password?\n");
	}
	else
	{
		fprintf(stderr, "redis SET error: state = %d, error = %d\n",
				state, task->get_error());
	}
}

void http_callback(WFHttpTask *task)
{
	HttpResponse *resp = task->get_resp();
	int state = task->get_state();
	int error = task->get_error();

	if (state != WFT_STATE_SUCCESS)
	{
		fprintf(stderr, "http task error: state = %d, error = %d\n",
						state, error);
		return;
	}

	SeriesWork *series = series_of(task);   /* get the series of this task */
	tutorial_series_context *context =
		(tutorial_series_context *)series->get_context();

	const void *body;
	size_t body_len;

	resp->get_parsed_body(&body, &body_len);
	if (body_len == 0)
	{
		fprintf(stderr, "Error: empty http body!");
		return;
	}

	context->body_len = body_len;

	WFRedisTask *redis_task =
		WFTaskFactory::create_redis_task(context->redis_url, RETRY_MAX,
										 redis_callback);

	std::string value((char *)body, body_len);
	redis_task->get_req()->set_request("SET", { context->http_url, value });
	*series << redis_task; /* equal to series->push_back(redis_task) */
}

int main(int argc, char *argv[])
{
	WFHttpTask *http_task;

	if (argc != 3)
	{
		fprintf(stderr, "USAGE: %s <http URL> <redis URL>\n", argv[0]);
		exit(1);
	}

	struct tutorial_series_context context;

	context.success = false;
	context.http_url = argv[1];
	if (strncasecmp(argv[1], "http://", 7) != 0 &&
		strncasecmp(argv[1], "https://", 8) != 0)
	{
		context.http_url = "http://" + context.http_url;
	}

	context.redis_url = argv[2];
	if (strncasecmp(argv[2], "redis://", 8) != 0 &&
		strncasecmp(argv[2], "rediss://", 9) != 0)
	{
		context.redis_url = "redis://" + context.redis_url;
	}

	http_task = WFTaskFactory::create_http_task(context.http_url,
												REDIRECT_MAX, RETRY_MAX,
												http_callback);
	HttpRequest *req = http_task->get_req();
	req->add_header_pair("Accept", "*/*");
	req->add_header_pair("User-Agent", "Wget/1.14 (linux-gnu)");
	req->add_header_pair("Connection", "close");

	/* Limit the http response size to 20M. */
	http_task->get_resp()->set_size_limit(20 * 1024 * 1024);

	/* no more than 30 seconds receiving http response. */
	http_task->set_receive_timeout(30 * 1000);

	WFFacilities::WaitGroup wait_group(1);

	auto series_callback = [&wait_group](const SeriesWork *series)
	{
		tutorial_series_context *context = (tutorial_series_context *)
											series->get_context();

		if (context->success)
			fprintf(stderr, "Series finished. all success!\n");
		else
			fprintf(stderr, "Series finished. failed!\n");

		/* signal the main() to terminate */
		wait_group.done();
	};

	/* Create a series */
	SeriesWork *series = Workflow::create_series_work(http_task,
													  series_callback);
	series->set_context(&context);
	series->start();

	wait_group.wait();
	return 0;
}


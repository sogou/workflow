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

#include <stdio.h>
#include <string.h>
#include <utility>
#include <string>
#include "workflow/Workflow.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/HttpMessage.h"
#include "workflow/HttpUtil.h"
#include "workflow/WFFacilities.h"

using namespace protocol;

#define REDIRECT_MAX    5
#define RETRY_MAX       2

struct tutorial_series_context
{
	std::string url;
	int state;
	int error;
	HttpResponse resp;
};

void callback(const ParallelWork *pwork)
{
	tutorial_series_context *ctx;
	const void *body;
	size_t size;
	size_t i;

	for (i = 0; i < pwork->size(); i++)
	{
		ctx = (tutorial_series_context *)pwork->series_at(i)->get_context();
		printf("%s\n", ctx->url.c_str());
		if (ctx->state == WFT_STATE_SUCCESS)
		{
			ctx->resp.get_parsed_body(&body, &size);
			printf("%zu%s\n", size, ctx->resp.is_chunked() ? " chunked" : "");
			fwrite(body, 1, size, stdout);
			printf("\n");
		}
		else
			printf("ERROR! state = %d, error = %d\n", ctx->state, ctx->error);

		delete ctx;
	}
}

int main(int argc, char *argv[])
{
	ParallelWork *pwork = Workflow::create_parallel_work(callback);
	SeriesWork *series;
	WFHttpTask *task;
	HttpRequest *req;
	tutorial_series_context *ctx;
	int i;

	for (i = 1; i < argc; i++)
	{
		std::string url(argv[i]);

		if (strncasecmp(argv[i], "http://", 7) != 0 &&
			strncasecmp(argv[i], "https://", 8) != 0)
		{
			url = "http://" +url;
		}

		task = WFTaskFactory::create_http_task(url, REDIRECT_MAX, RETRY_MAX,
			[](WFHttpTask *task)
		{
			tutorial_series_context *ctx =
				(tutorial_series_context *)series_of(task)->get_context();
			ctx->state = task->get_state();
			ctx->error = task->get_error();
			ctx->resp = std::move(*task->get_resp());
		});

		req = task->get_req();
		req->add_header_pair("Accept", "*/*");
		req->add_header_pair("User-Agent", "Wget/1.14 (linux-gnu)");
		req->add_header_pair("Connection", "close");

		ctx = new tutorial_series_context;
		ctx->url = std::move(url);
		series = Workflow::create_series_work(task, nullptr);
		series->set_context(ctx);
		pwork->add_series(series);
	}

	WFFacilities::WaitGroup wait_group(1);

	Workflow::start_series_work(pwork, [&wait_group](const SeriesWork *) {
		wait_group.done();
	});

	wait_group.wait();
	return 0;
}


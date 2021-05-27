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

  Author: Xie Han (xiehan@sogou-inc.com;63350856@qq.com)
*/

#include <stdio.h>
#include "workflow/WFTaskFactory.h"
#include "workflow/WFGraphTask.h"
#include "workflow/HttpMessage.h"
#include "workflow/WFFacilities.h"

using namespace protocol;

static WFFacilities::WaitGroup wait_group(1);

void go_func(const size_t *size1, const size_t *size2)
{
	printf("page1 size = %zu, page2 size = %zu\n", *size1, *size2);
}

void http_callback(WFHttpTask *task)
{
	size_t *size = (size_t *)task->user_data;
	const void *body;

	if (task->get_state() == WFT_STATE_SUCCESS)
		task->get_resp()->get_parsed_body(&body, size);
	else
		*size = (size_t)-1;
}

#define REDIRECT_MAX	3
#define RETRY_MAX		1

int main()
{
	WFTimerTask *timer;
	WFHttpTask *http_task1;
	WFHttpTask *http_task2;
	WFGoTask *go_task;
	size_t size1;
	size_t size2;

	timer = WFTaskFactory::create_timer_task(1000000, [](WFTimerTask *) {
		printf("timer task complete(1s).\n");
	});

	/* Http task1 */
	http_task1 = WFTaskFactory::create_http_task("https://www.sogou.com/",
												 REDIRECT_MAX, RETRY_MAX,
												 http_callback);
	http_task1->user_data = &size1;

	/* Http task2 */
	http_task2 = WFTaskFactory::create_http_task("https://www.baidu.com/",
												 REDIRECT_MAX, RETRY_MAX,
												 http_callback);
	http_task2->user_data = &size2;

	/* go task will print the http pages size */
	go_task = WFTaskFactory::create_go_task("go", go_func, &size1, &size2);

	/* Create a graph. Graph is also a kind of task */
	WFGraphTask *graph = WFTaskFactory::create_graph_task([](WFGraphTask *) {
		printf("Graph task complete. Wakeup main process\n");
		wait_group.done();
	});

	/* Create graph nodes */
	WFGraphNode& a = graph->create_graph_node(timer);
	WFGraphNode& b = graph->create_graph_node(http_task1);
	WFGraphNode& c = graph->create_graph_node(http_task2);
	WFGraphNode& d = graph->create_graph_node(go_task);

	/* Build the graph */
	a-->b;
	a-->c;
	b-->d;
	c-->d;

	graph->start();
	wait_group.wait();
	return 0;
}


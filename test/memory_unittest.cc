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

  Author: Liu Yang (liuyang216492@sogou-inc.com)
*/

#include <vector>
#include <gtest/gtest.h>
#include "workflow/WFTaskFactory.h"

TEST(memory_unittest, dismiss)
{
	std::vector<SubTask *> tasks;

	auto *http_task = WFTaskFactory::create_http_task("http://www.sogou.com", 0, 0, nullptr);
	tasks.push_back(http_task);

	auto *redis_task = WFTaskFactory::create_redis_task("redis://username:password@127.0.0.1:6676/1", 0, nullptr);
	tasks.push_back(redis_task);

	auto *mysql_task = WFTaskFactory::create_mysql_task("mysql://username:password@127.0.0.1:8899/db", 0, nullptr);
	tasks.push_back(mysql_task);

	auto *timer_task = WFTaskFactory::create_timer_task(0, nullptr);
	tasks.push_back(timer_task);

	auto *counter_task = WFTaskFactory::create_counter_task("", 1, nullptr);
	tasks.push_back(counter_task);

	auto *go_task = WFTaskFactory::create_go_task("", [](){});
	tasks.push_back(go_task);

	auto *thread_task = WFThreadTaskFactory<int, int>::create_thread_task("", [](int *, int *){}, nullptr);
	tasks.push_back(thread_task);

	auto *graph_task = WFTaskFactory::create_graph_task(nullptr);
	auto& node_a = graph_task->create_graph_node(WFTaskFactory::create_timer_task(0, nullptr));
	auto& node_b = graph_task->create_graph_node(WFTaskFactory::create_timer_task(0, nullptr));
	node_a -->-- node_b;
	tasks.push_back(graph_task);
	
	auto *parallel_work = Workflow::create_parallel_work(nullptr);
	for (auto *task : tasks)
	{
		auto *series_work = Workflow::create_series_work(task, nullptr);
		parallel_work->add_series(series_work);
	}

	parallel_work->dismiss();
}

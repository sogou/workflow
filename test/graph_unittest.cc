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

#include <atomic>
#include <gtest/gtest.h>

#include "workflow/WFTaskFactory.h"
#include "workflow/WFFacilities.h"

static SubTask *create_task(int& target)
{
	static std::atomic<int> generator;
	return WFTaskFactory::create_timer_task(0, [&](WFTimerTask *)
	{
		target = generator++;
	});
}

TEST(graph_unittest, WFGraphTask1)
{
	WFFacilities::WaitGroup wait_group(1);

	auto graph = WFTaskFactory::create_graph_task([&wait_group](WFGraphTask *){ wait_group.done(); });

	int ta, tb, tc, td;

	auto& a = graph->create_graph_node(create_task(ta));
	auto& b = graph->create_graph_node(create_task(tb));
	auto& c = graph->create_graph_node(create_task(tc));
	auto& d = graph->create_graph_node(create_task(td));

	a --> b <-- c --> d --> a;
	c --> a;

	graph->start();
	wait_group.wait();

	EXPECT_LT(ta, tb);
	EXPECT_LT(tc, tb);
	EXPECT_LT(tc, td);
	EXPECT_LT(td, ta);
	EXPECT_LT(tc, ta);
}

TEST(graph_unittest, WFGraphTask2)
{
	WFFacilities::WaitGroup wait_group(1);

	auto graph = WFTaskFactory::create_graph_task([&wait_group](WFGraphTask *){ wait_group.done(); });

	constexpr int N = 4096 - 1;

	auto target = new int[N];
	auto node = new WFGraphNode *[N];

	for (int i = 0; i < N; i++)
		node[i] = &graph->create_graph_node(create_task(target[i]));

	for (int i = 1; i < N; i++)
		node[i]->precede(*node[(i - 1) / 2]);

	graph->start();
	wait_group.wait();

	for (int i = 1; i < N; i++)
		EXPECT_LT(target[i], target[(i - 1) / 2]);

	delete[] target;
	delete[] node;
}

#include <vector>
#include <gtest/gtest.h>
#include "workflow/WFTaskFactory.h"

TEST(memory_unittest, dismiss)
{
	std::vector<SubTask *> tasks;

	auto http_task = WFTaskFactory::create_http_task("https://sogou.com", 0, 0, nullptr);
	tasks.push_back(http_task);

	auto redis_task = WFTaskFactory::create_redis_task("redis://username:password@127.0.0.1:6676/1", 0, nullptr);
	tasks.push_back(redis_task);

	auto mysql_task = WFTaskFactory::create_mysql_task("mysql://username:password@127.0.0.1:8899/db", 0, nullptr);
	tasks.push_back(mysql_task);

	auto timer_task = WFTaskFactory::create_timer_task(0, nullptr);
	tasks.push_back(timer_task);

	auto counter_task = WFTaskFactory::create_counter_task("", 0, nullptr);
	tasks.push_back(counter_task);

	auto go_task = WFTaskFactory::create_go_task("", [](){});
	tasks.push_back(go_task);

	auto thread_task = WFThreadTaskFactory<int, int>::create_thread_task("", [](int *, int *){}, nullptr);
	tasks.push_back(thread_task);

	auto graph_task = WFTaskFactory::create_graph_task(nullptr);
	auto &node_a = graph_task->create_graph_node(WFTaskFactory::create_timer_task(0, nullptr));
	auto &node_b = graph_task->create_graph_node(WFTaskFactory::create_timer_task(0, nullptr));
	node_a -->-- node_b;
	tasks.push_back(graph_task);
	
	auto parallel_work = Workflow::create_parallel_work(nullptr);
	for (auto task : tasks)
	{
		auto series_work = Workflow::create_series_work(task, nullptr);
		parallel_work->add_series(series_work);
	}

	parallel_work->dismiss();
}

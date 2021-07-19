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

  Author: Li Yingxin (liyingxin@sogou-inc.com)
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <chrono>
#include <mutex>
#include <gtest/gtest.h>
#include "workflow/WFTask.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/WFResourcePool.h"
#include "workflow/WFCondition.h"
#include "workflow/WFCondTaskFactory.h"
#include "workflow/WFFacilities.h"

TEST(condition_unittest, signal)
{
	WFCondition cond;
	std::mutex mutex;
	WFFacilities::WaitGroup wg(1);
	int ret = 3;
	int *ptr = &ret;

	auto *task1 = WFCondTaskFactory::create_wait_task(&cond, [&wg, &ptr](WFMailboxTask *) {
		*ptr = 1;
		wg.done();
	});

	auto *task2 = WFCondTaskFactory::create_wait_task(&cond, [&ptr](WFMailboxTask *) {
		*ptr = 2;
	});

	SeriesWork *series1 = Workflow::create_series_work(task1, nullptr);
	SeriesWork *series2 = Workflow::create_series_work(task2, nullptr);

	series1->start();
	series2->start();

	mutex.lock();
	cond.signal(NULL);
	mutex.unlock();
	wg.wait();
	EXPECT_EQ(ret, 1);
	cond.signal(NULL);
	usleep(1000);
	EXPECT_EQ(ret, 2);
}

TEST(condition_unittest, broadcast)
{
	WFCondition cond;
	std::mutex mutex;
	int ret = 0;
	int *ptr = &ret;

	auto *task1 = WFCondTaskFactory::create_wait_task(&cond, [&ptr](WFMailboxTask *) {
		(*ptr)++;
	});
	SeriesWork *series1 = Workflow::create_series_work(task1, nullptr);

	auto *task2 = WFCondTaskFactory::create_wait_task(&cond, [&ptr](WFMailboxTask *) {
		(*ptr)++;
	});
	SeriesWork *series2 = Workflow::create_series_work(task2, nullptr);

	series1->start();
	series2->start();

	cond.broadcast(NULL);
	usleep(1000);
	EXPECT_EQ(ret, 2);
}

TEST(condition_unittest, timedwait)
{
	WFFacilities::WaitGroup wait_group(2);
	struct timespec ts;
	ts.tv_sec = 1;
	ts.tv_nsec = 0;

	auto *task1 = WFCondTaskFactory::create_timedwait_task("timedwait1", &ts,
		[&wait_group](WFMailboxTask *task) {
		EXPECT_EQ(task->get_error(), ETIMEDOUT);
		wait_group.done();
	});

	auto *task2 = WFCondTaskFactory::create_timedwait_task("timedwait2", &ts,
		[&wait_group](WFMailboxTask *task) {
		EXPECT_EQ(task->get_error(), 0);
		void **msg;
		size_t n;
		msg = task->get_mailbox(&n);
		EXPECT_EQ(n, 1);
		EXPECT_TRUE(strcmp((char *)*msg, "wake up!!") == 0);
		wait_group.done();
	});

	Workflow::start_series_work(task1, nullptr);
	Workflow::start_series_work(task2, nullptr);

	usleep(1000);
	char msg[10] = "wake up!!";
	WFCondTaskFactory::signal_by_name("timedwait2", msg);
	wait_group.wait();
}

TEST(condition_unittest, resource_pool)
{
	int res_concurrency = 3;
	int task_concurrency = 10;
	const char *words[3] = {"workflow", "srpc", "pyworkflow"};
	WFResourcePool res_pool((void **)words, res_concurrency);
	WFFacilities::WaitGroup wg(task_concurrency);

	for (int i = 0; i < task_concurrency; i++)
	{
		auto *user_task = WFTaskFactory::create_timer_task(0,
		[&wg, &res_pool](WFTimerTask *task) {
			uint64_t id = (uint64_t)series_of(task)->get_context();
			printf("task-%lu get [%s]\n", id, (char *)task->user_data);
			res_pool.post(task->user_data);
			wg.done();
		});

		auto *cond = res_pool.get(user_task, &user_task->user_data);

		SeriesWork *series = Workflow::create_series_work(cond, nullptr);
		series->set_context(reinterpret_cast<uint64_t *>(i));
		series->start();
	}

	wg.wait();
}

class TestResource : public WFCondition::BaseResource
{
public:
	TestResource(std::string msg) : msg(msg) { }
	void *get() { return &this->msg; }
	void set(std::string&& msg) { this->msg = std::move(msg);}

private:
	std::string msg;
};

TestResource res("");

void wait_callback(WFWaitTask *task)
{
	void **msg;
	size_t n;
	msg = task->get_mailbox(&n);
	std::string *str = *msg;
	fprintf(stderr, "waiter get msg:%s\n", str->c_str());
	series->set_context(*msg);
}

void work(std::string *msg, WFFacilities::WaitGroup &wg)
{
	fprintf(stderr, "working on message:%s\n", msg->c_str());
	wg.done();
}

SubTask *create_router_task(WFCondition *cond, std::function<WFTimerTask *task> cb)
{
	auto *router = WFTaskFactory::create_timer_task(100000, std::move(cb));
	router->user_data = cond;
}

void router_callback(WFTimerTask *task)
{
	fprintf(stderr, "finish routing and should broadcast every one else\n");
	
	((WFCondition *)(task->user_data))->broadcast();
}

TEST(condition_unittest, res_condition)
{
	int task_concurrency = 10;
	WFFacilities::WaitGroup wg(task_concurrency);
	WFCondition cond((WFCondition::BaseResource *)&res);

	for (int i = 0; i < task_concurrency; i++)
	{
		auto *timer = WFTaskFactory::create_timer_task(i * 100000,
		[&cond](WFTimerTask *task) {
			std::string *msg;
			int ret = cond.get(&msg);
			if (ret == -1)
			{
				auto *waiter = cond.create_wait_task(wait_callback);
				series_of(task)->push_front(waiter);
				fprintf(stderr, "task-%lu waiting\n", id);
			}
			else if (ret == 0)
			{
				auto *router = create_router_task(route_callback);
				series_of(task)->push_front(router);
				fprintf(stderr, "task-%lu routing\n", id);
			}
			else
			{
				fprintf(stderr, "task-%lu get [%s]\n", id, (*msg).c_str());
			}
		});

		SeriesWork *series = Workflow::create_series_work(timer, nullptr);
		auto *worker = WFTaskFactory::create_go_task(work,
													 (std::string *)series->get_context(),
													 &wg);
		series->push_back(worker);
		series->start();
	}

	wg.wait();
}


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

#include <gtest/gtest.h>
#include "workflow/UpstreamManager.h"
#include "workflow/WFHttpServer.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/WFFacilities.h"
#include "workflow/UpstreamPolicies.h"

#define REDIRECT_MAX	2
#define RETRY_MAX		2
#define MTTR			2
#define MAX_FAILS		200

static void __http_process(WFHttpTask *task, const char *name)
{
	auto *resp = task->get_resp();
	resp->add_header_pair("Content-Type", "text/plain");
	resp->append_output_body_nocopy(name, strlen(name));
}

WFHttpServer http_server1(std::bind(&__http_process,
									std::placeholders::_1,
									"server1"));
WFHttpServer http_server2(std::bind(&__http_process,
									std::placeholders::_1,
									"server2"));
WFHttpServer http_server3(std::bind(&__http_process,
									std::placeholders::_1,
									"server3"));

void register_upstream_hosts()
{
	UpstreamManager::upstream_create_weighted_random("weighted.random", false);
	AddressParams address_params = ADDRESS_PARAMS_DEFAULT;
	address_params.weight = 1000;
	UpstreamManager::upstream_add_server("weighted.random",
										 "127.0.0.1:8001",
										 &address_params);
	address_params.weight = 1;
	UpstreamManager::upstream_add_server("weighted.random",
										 "127.0.0.1:8002",
										 &address_params);

	UpstreamManager::upstream_create_consistent_hash(
	"hash",
	[](const char *path, const char *query, const char *fragment) -> unsigned int {
		return 4250947057; // test skip from the end to the begin, hit 8002
	});
	UpstreamManager::upstream_add_server("hash", "127.0.0.1:8001");
	UpstreamManager::upstream_add_server("hash", "127.0.0.1:8001");
	UpstreamManager::upstream_add_server("hash", "127.0.0.1:8002");

	UpstreamManager::upstream_create_manual(
	"manual",
	[](const char *path, const char *query, const char *fragment) -> unsigned int {
		return 0;
	},
	true,
	[](const char *path, const char *query, const char *fragment) -> unsigned int {
		return 511702306; // test skip the non-alive server
	});
	UpstreamManager::upstream_add_server("manual", "127.0.0.1:8001");
	UpstreamManager::upstream_add_server("manual", "127.0.0.1:8002");

	UpstreamManager::upstream_create_round_robin("round.robin", true);
	UpstreamManager::upstream_add_server("round.robin", "127.0.0.1:8001");
	UpstreamManager::upstream_add_server("round.robin", "127.0.0.1:8002");

	UpstreamManager::upstream_create_manual(
	"try_another",
	[](const char *path, const char *query, const char *fragment) -> unsigned int {
		return 0;
	},
	false, nullptr);
	UpstreamManager::upstream_add_server("try_another", "127.0.0.1:8001");
	UpstreamManager::upstream_add_server("try_another", "127.0.0.1:8002");

	UpstreamManager::upstream_create_weighted_random("test_tracing", true);
	address_params.weight = 1000;
	UpstreamManager::upstream_add_server("test_tracing",
										 "127.0.0.1:8001",
										 &address_params);
	address_params.weight = 1;
	UpstreamManager::upstream_add_server("test_tracing",
										 "127.0.0.1:8002",
										 &address_params);
	address_params.weight = 1000;
	UpstreamManager::upstream_add_server("test_tracing",
										 "127.0.0.1:8003",
										 &address_params);
}

void basic_callback(WFHttpTask *task, std::string& message)
{
	int state = task->get_state();
	EXPECT_EQ(state, WFT_STATE_SUCCESS);
	if (state == WFT_STATE_SUCCESS && message.compare(""))
	{
		const void *body;
		size_t body_len;
		task->get_resp()->get_parsed_body(&body, &body_len);
		std::string buffer((char *)body, body_len);
		EXPECT_EQ(buffer, message);
	}
	WFFacilities::WaitGroup *wait_group = (WFFacilities::WaitGroup *)task->user_data;
	wait_group->done();
}

TEST(upstream_unittest, BasicPolicy)
{
	WFFacilities::WaitGroup wait_group(5);
	WFHttpTask *task1;
	WFHttpTask *task2;

	char url[4][30] = {"http://weighted.random", "http://manual",
						"http://hash", "http://round.robin"};

	http_callback_t cb1 = std::bind(basic_callback, std::placeholders::_1,
								    std::string("server1"));
	for (int i = 0; i < 2; i++)
	{
		task1 = WFTaskFactory::create_http_task(url[i], REDIRECT_MAX,
												RETRY_MAX, cb1);
		task1->user_data = &wait_group;
		task1->start();
	}

	http_callback_t cb2 = std::bind(basic_callback, std::placeholders::_1,
								    std::string("server2"));

	task2 = WFTaskFactory::create_http_task(url[2], REDIRECT_MAX,
											RETRY_MAX, cb2);
	task2->user_data = &wait_group;
	task2->start();

	task1 = WFTaskFactory::create_http_task(url[3], REDIRECT_MAX,
											RETRY_MAX, cb1);
	task1->user_data = &wait_group;

	task2 = WFTaskFactory::create_http_task(url[3], REDIRECT_MAX,
											RETRY_MAX, cb2);
	task2->user_data = &wait_group;

	SeriesWork *series = Workflow::create_series_work(task1, nullptr);
	series->push_back(task2);
	series->start();

	wait_group.wait();
}

TEST(upstream_unittest, EnableAndDisable)
{
	WFFacilities::WaitGroup wait_group(1);

	UpstreamManager::upstream_disable_server("weighted.random", "127.0.0.1:8001");

	std::string url = "http://weighted.random";
	WFHttpTask *task = WFTaskFactory::create_http_task(url, REDIRECT_MAX, RETRY_MAX,
										[&wait_group, &url](WFHttpTask *task){
		int state = task->get_state();
		EXPECT_EQ(state, WFT_STATE_TASK_ERROR);
		EXPECT_EQ(task->get_error(), WFT_ERR_UPSTREAM_UNAVAILABLE);
		UpstreamManager::upstream_enable_server("weighted.random", "127.0.0.1:8001");
		auto *task2 = WFTaskFactory::create_http_task(url, REDIRECT_MAX, RETRY_MAX,
													  std::bind(basic_callback,
																std::placeholders::_1,
																std::string("server1")));
		task2->user_data = &wait_group;
		series_of(task)->push_back(task2);
	});
	task->user_data = &wait_group;
	task->start();	

	wait_group.wait();
}

TEST(upstream_unittest, AddAndRemove)
{
	WFFacilities::WaitGroup wait_group(2);
	WFHttpTask *task;
	SeriesWork *series;
	protocol::HttpRequest *req;
	int batch = MAX_FAILS + 50;
	std::string url = "http://add_and_remove";
	std::string name = "add_and_remove";
	UPSWeightedRandomPolicy test_policy(false);

	AddressParams address_params = ADDRESS_PARAMS_DEFAULT;

	address_params.weight = 1000;
	test_policy.add_server("127.0.0.1:8001", &address_params);

	address_params.weight = 1;
	test_policy.add_server("127.0.0.1:8002", &address_params);

	auto *ns = WFGlobal::get_name_service();
	EXPECT_EQ(ns->add_policy(name.c_str(), &test_policy), 0);

	UpstreamManager::upstream_remove_server(name, "127.0.0.1:8001");
	task = WFTaskFactory::create_http_task(url, REDIRECT_MAX, RETRY_MAX,
										   std::bind(basic_callback,
													 std::placeholders::_1,
													 std::string("server2")));
	task->user_data = &wait_group;
	task->start();

	//test remove fused server
	address_params.weight = 1000;
	test_policy.add_server("127.0.0.1:8001", &address_params);
	http_server1.stop();

	fprintf(stderr, "server 1 stopped start %d tasks to fuse it\n", batch);
	ParallelWork *pwork = Workflow::create_parallel_work(
										[&wait_group, &name, &url](const ParallelWork *pwork) {
		fprintf(stderr, "parallel finished and remove server1\n");
		UpstreamManager::upstream_remove_server(name, "127.0.0.1:8001");
		auto *task = WFTaskFactory::create_http_task(url, REDIRECT_MAX, RETRY_MAX,
													 std::bind(basic_callback,
													 std::placeholders::_1,
								 					 std::string("server2")));
		task->user_data = &wait_group;
		series_of(pwork)->push_back(task);
	});

	for (int i = 0; i < batch; i++)
	{
		task = WFTaskFactory::create_http_task(url, 0, 0, nullptr);
		req = task->get_req();
		req->add_header_pair("Connection", "keep-alive");
		series = Workflow::create_series_work(task, nullptr);
		pwork->add_series(series);
	}

	pwork->start();
	wait_group.wait();
	EXPECT_TRUE(http_server1.start("127.0.0.1", 8001) == 0)
				<< "http server start failed";
	ns->del_policy(name.c_str());
}

TEST(upstream_unittest, FuseAndRecover)
{
	WFFacilities::WaitGroup wait_group(1);
	WFHttpTask *task;
	SeriesWork *series;
	protocol::HttpRequest *req;
	std::string url = "http://test_policy";
	int batch = MAX_FAILS + 50;
	int timeout = (MTTR + 1) * 1000000;

	UPSWeightedRandomPolicy test_policy(false);
	test_policy.set_mttr_second(MTTR);
	AddressParams address_params = ADDRESS_PARAMS_DEFAULT;
	
	address_params.weight = 1000;
	test_policy.add_server("127.0.0.1:8001", &address_params);

	address_params.weight = 1;
	test_policy.add_server("127.0.0.1:8002", &address_params);

	auto *ns = WFGlobal::get_name_service();
	EXPECT_EQ(ns->add_policy("test_policy", &test_policy), 0);

	http_server1.stop();
	fprintf(stderr, "server 1 stopped start %d tasks to fuse it\n", batch);
	ParallelWork *pwork = Workflow::create_parallel_work(
										[](const ParallelWork *pwork) {
		fprintf(stderr, "parallel finished\n");
	});

	for (int i = 0; i < batch; i++)
	{
		task = WFTaskFactory::create_http_task(url, 0, 0, nullptr);
		req = task->get_req();
		req->add_header_pair("Connection", "keep-alive");
		series = Workflow::create_series_work(task, nullptr);
		pwork->add_series(series);
	}

	series = Workflow::create_series_work(pwork, nullptr);

	WFTimerTask *timer = WFTaskFactory::create_timer_task(timeout,
														  [](WFTimerTask *task) {
		fprintf(stderr, "timer_finished and start server1\n");
		EXPECT_TRUE(http_server1.start("127.0.0.1", 8001) == 0)
					<< "http server start failed";
	});

	series->push_back(timer);

	task = WFTaskFactory::create_http_task(url, REDIRECT_MAX, RETRY_MAX,
										   std::bind(basic_callback,
													 std::placeholders::_1,
								 					 std::string("server1")));
	task->user_data = &wait_group;
	series->push_back(task);

	series->start();
	wait_group.wait();
	ns->del_policy("test_policy");
}

TEST(upstream_unittest, TryAnother)
{
	WFFacilities::WaitGroup wait_group(3);

	UpstreamManager::upstream_disable_server("manual", "127.0.0.1:8001");
	UpstreamManager::upstream_disable_server("round.robin", "127.0.0.1:8001");
	UpstreamManager::upstream_disable_server("try_another", "127.0.0.1:8001");

	http_callback_t cb2 = std::bind(basic_callback, std::placeholders::_1,
								    std::string("server2"));

	WFHttpTask *task = WFTaskFactory::create_http_task("http://manual",
													   REDIRECT_MAX, RETRY_MAX,
													   cb2);
	task->user_data = &wait_group;
	task->start();

	// this->cur_idx == 1. Will skip 8001 and try 8002.
	task = WFTaskFactory::create_http_task("http://round.robin",
										   REDIRECT_MAX, RETRY_MAX, cb2);
	task->user_data = &wait_group;
	task->start();

	task = WFTaskFactory::create_http_task("http://try_another",
										   REDIRECT_MAX, RETRY_MAX,
										   [&wait_group](WFHttpTask *task){
		int state = task->get_state();
		EXPECT_EQ(state, WFT_STATE_TASK_ERROR);
		EXPECT_EQ(task->get_error(), WFT_ERR_UPSTREAM_UNAVAILABLE);
		wait_group.done();
	});
	task->start();

	wait_group.wait();
	UpstreamManager::upstream_enable_server("manual", "127.0.0.1:8001");
	UpstreamManager::upstream_enable_server("round.robin", "127.0.0.1:8001");
	UpstreamManager::upstream_enable_server("try_another", "127.0.0.1:8001");
}

TEST(upstream_unittest, Tracing)
{
	WFFacilities::WaitGroup wait_group(2);

	http_server1.stop();

	// test first_strategy()
	WFHttpTask *task = WFTaskFactory::create_http_task(
											"http://weighted.random",
											REDIRECT_MAX, RETRY_MAX,
											std::bind(basic_callback,
													  std::placeholders::_1,
								   					  std::string("server2")));
	task->user_data = &wait_group;
	task->start();

	// test another_strategy()
	UpstreamManager::upstream_disable_server("test_tracing",
											 "127.0.0.1:8003");
	WFHttpTask *task2 = WFTaskFactory::create_http_task(
											"http://test_tracing",
											REDIRECT_MAX, RETRY_MAX,
											std::bind(basic_callback,
													  std::placeholders::_1,
								   					  std::string("server2")));
	task2->user_data = &wait_group;
	task2->start();

	wait_group.wait();
	EXPECT_TRUE(http_server1.start("127.0.0.1", 8001) == 0)
				<< "http server start failed";
	UpstreamManager::upstream_enable_server("test_tracing", "127.0.0.1:8003");
}


TEST(upstream_unittest, RoundRobin)
{
	WFFacilities::WaitGroup wait_group(1);

	// this->cur_idx = 0. When 8002 is removed, we will try 8001.
	UpstreamManager::upstream_remove_server("round.robin", "127.0.0.1:8002");
	WFHttpTask *task = WFTaskFactory::create_http_task("http://round.robin",
													REDIRECT_MAX, RETRY_MAX,
													std::bind(basic_callback,
													std::placeholders::_1,
													std::string("server1")));
	task->user_data = &wait_group;
	task->start();

	wait_group.wait();
	UpstreamManager::upstream_add_server("round.robin", "127.0.0.1:8002");
}

int main(int argc, char* argv[])
{
	::testing::InitGoogleTest(&argc, argv);

	register_upstream_hosts();

	EXPECT_TRUE(http_server1.start("127.0.0.1", 8001) == 0)
				<< "http server start failed";

	EXPECT_TRUE(http_server2.start("127.0.0.1", 8002) == 0)
				<< "http server start failed";

	EXPECT_TRUE(http_server3.start("127.0.0.1", 8003) == 0)
				<< "http server start failed";
		
	EXPECT_EQ(RUN_ALL_TESTS(), 0);

	EXPECT_EQ(UpstreamManager::upstream_delete("try_another"), 0);
	EXPECT_EQ(UpstreamManager::upstream_delete("try_another"), -1);

	http_server1.stop();
	http_server2.stop();
	http_server3.stop();

	return 0;
}


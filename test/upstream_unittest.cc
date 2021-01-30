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

  Author: Li Yingxin (liyingxin@sogou-inc.com)
*/

#include <gtest/gtest.h>
#include "workflow/UpstreamManager.h"
#include "workflow/WFHttpServer.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/WFFacilities.h"

#define REDIRECT_MAX	3
#define RETRY_MAX		3
#define MTTR			30
#define MAX_FAILS		200

static void __http_process1(WFHttpTask *task)
{
	auto *resp = task->get_resp();
	resp->add_header_pair("Content-Type", "text/plain");
	resp->append_output_body_nocopy("server1", 7);
}

static void __http_process2(WFHttpTask *task)
{
	auto *resp = task->get_resp();
	resp->add_header_pair("Content-Type", "text/plain");
	resp->append_output_body_nocopy("server2", 7);
}

WFHttpServer http_server1(__http_process1);
WFHttpServer http_server2(__http_process2);

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
		return 1;
	});
	UpstreamManager::upstream_add_server("hash", "127.0.0.1:8001");
	UpstreamManager::upstream_add_server("hash", "127.0.0.1:8002");

	UpstreamManager::upstream_create_manual(
    "manual",
    [](const char *path, const char *query, const char *fragment) -> unsigned int {
		return 0;
	},
	false, nullptr);
	UpstreamManager::upstream_add_server("manual", "127.0.0.1:8001");
	UpstreamManager::upstream_add_server("manual", "127.0.0.1:8002");

	UpstreamManager::upstream_create_weighted_random("try_another", true);
	address_params.weight = 1000;
	UpstreamManager::upstream_add_server("try_another",
										 "127.0.0.1:8001",
										 &address_params);
	address_params.weight = 1;
	UpstreamManager::upstream_add_server("try_another",
										 "127.0.0.1:8002",
										 &address_params);
}

void basic_callback(WFHttpTask *task, std::string& message)
{
	auto state = task->get_state();
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
	WFFacilities::WaitGroup wait_group(3);

	register_upstream_hosts();

	char url[3][30] = {"http://weighted.random", "http://hash", "http://manual"};

	http_callback_t cb = std::bind(basic_callback, std::placeholders::_1,
								   std::string("server1"));
	for (int i = 0; i < 3; i++)
	{
		WFHttpTask *task = WFTaskFactory::create_http_task(url[i],
											  REDIRECT_MAX, RETRY_MAX, cb);
		task->user_data = &wait_group;
		task->start();
	}

	wait_group.wait();
}

TEST(upstream_unittest, EnableAndDisable)
{
	WFFacilities::WaitGroup wait_group(1);

	UpstreamManager::upstream_disable_server("weighted.random", "127.0.0.1:8001");

	//fprintf(stderr, "disable server and try......................\n");
	std::string url = "http://weighted.random";
	WFHttpTask *task = WFTaskFactory::create_http_task(url, REDIRECT_MAX, RETRY_MAX,
											  		   [&wait_group, &url](WFHttpTask *task){
		auto state = task->get_state();
		EXPECT_EQ(state, WFT_STATE_TASK_ERROR);
		EXPECT_EQ(task->get_error(), WFT_ERR_UPSTREAM_UNAVAILABLE);
		UpstreamManager::upstream_enable_server("weighted.random", "127.0.0.1:8001");
		//fprintf(stderr, "ensable server and try......................\n");
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

TEST(upstream_unittest, FuseAndRecover)
{
	WFFacilities::WaitGroup wait_group(1);
	WFHttpTask *task;
	SeriesWork *series;
	protocol::HttpRequest *req;
	std::string url = "http://weighted.random";
	int batch = MAX_FAILS + 50;
	int timeout = (MTTR + 3) * 1000000;
	
	http_server1.stop();
	fprintf(stderr, "server 1 stopped start %d tasks to fuse it\n", batch);
	ParallelWork *pwork = Workflow::create_parallel_work(
										[](const ParallelWork *pwork) {
		fprintf(stderr, "parallel finished\n");
	});

	for (int i = 0; i < batch; i++)
	{
		task = WFTaskFactory::create_http_task(url, REDIRECT_MAX, RETRY_MAX,
										   nullptr);
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
}

TEST(upstream_unittest, TryAnother)
{
	WFFacilities::WaitGroup wait_group(1);

	UpstreamManager::upstream_disable_server("try_another", "127.0.0.1:8001");

	std::string url = "http://try_another";
	WFHttpTask *task = WFTaskFactory::create_http_task(url, REDIRECT_MAX, RETRY_MAX,
													   std::bind(basic_callback,
													  			 std::placeholders::_1,
								   								 std::string("server2")));
		
	task->user_data = &wait_group;
	task->start();
	wait_group.wait();
	UpstreamManager::upstream_enable_server("try_another", "127.0.0.1:8001");
}

int main(int argc, char* argv[])
{
	::testing::InitGoogleTest(&argc, argv);

	EXPECT_TRUE(http_server1.start("127.0.0.1", 8001) == 0)
				<< "http server start failed";

	EXPECT_TRUE(http_server2.start("127.0.0.1", 8002) == 0)
				<< "http server start failed";
	
	EXPECT_EQ(RUN_ALL_TESTS(), 0);

	http_server1.stop();
	http_server2.stop();

	return 0;
}


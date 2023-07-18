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

  Author: Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

#include <string.h>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <vector>
#include <string>
#include <gtest/gtest.h>
#include "workflow/WFTaskFactory.h"
#include "workflow/WFRedisServer.h"
#include "workflow/WFOperator.h"

#define RETRY_MAX  3

static void __redis_process(WFRedisTask *task)
{
	auto *req = task->get_req();
	auto *resp = task->get_resp();

	EXPECT_TRUE(req->parse_success());

	std::string cmd;
	std::vector<std::string> params;
	protocol::RedisValue val;

	EXPECT_TRUE(req->get_command(cmd));
	EXPECT_TRUE(req->get_params(params));

	if (strcasecmp(cmd.c_str(), "SET") == 0)
	{
		EXPECT_EQ(params.size(), 2);
		EXPECT_TRUE(params[0] == "testkey");
		EXPECT_TRUE(params[1] == "testvalue");
		val.set_status("OK");
	}
	else if (strcasecmp(cmd.c_str(), "GET") == 0)
	{
		EXPECT_EQ(params.size(), 1);
		val.set_string("testvalue");
	}
	else if (strcasecmp(cmd.c_str(), "DEL") == 0)
	{
		EXPECT_EQ(params.size(), 1);
		EXPECT_TRUE(params[0] == "testkey");
		val.set_status("OK");
	}
	else if (strcasecmp(cmd.c_str(), "SELECT") == 0)
	{
		EXPECT_EQ(params.size(), 1);
		EXPECT_TRUE(params[0] == "6");
		val.set_status("OK");
	}
	else if (strcasecmp(cmd.c_str(), "AUTH") == 0)
	{
		EXPECT_EQ(params.size(), 1);
		EXPECT_TRUE(params[0] == "testpass");
		val.set_status("OK");
	}
	else
	{
		EXPECT_TRUE(0) << "Command Not Support";
		val.set_error("Command Not Support");
	}

	resp->set_result(val);
}

static void test_client(const char *url, std::mutex& mutex, std::condition_variable& cond, bool& done)
{
	auto&& set_cb = [](WFRedisTask *task) {
		auto state = task->get_state();
		auto *resp = task->get_resp();
		protocol::RedisValue val;

		EXPECT_EQ(state, WFT_STATE_SUCCESS);
		EXPECT_TRUE(resp->parse_success());
		resp->get_result(val);
		EXPECT_TRUE(val.is_ok());
	};

	auto&& get_cb = [](WFRedisTask *task) {
		auto state = task->get_state();
		auto *resp = task->get_resp();
		protocol::RedisValue val;

		EXPECT_EQ(state, WFT_STATE_SUCCESS);
		EXPECT_TRUE(resp->parse_success());
		resp->get_result(val);
		EXPECT_TRUE(val.is_string());
		EXPECT_TRUE(val.string_value() == "testvalue");
	};

	auto&& del_cb = [](WFRedisTask *task) {
		auto state = task->get_state();
		auto *resp = task->get_resp();
		protocol::RedisValue val;

		EXPECT_EQ(state, WFT_STATE_SUCCESS);
		EXPECT_TRUE(resp->parse_success());
		resp->get_result(val);
		EXPECT_TRUE(val.is_ok());
	};

	auto *A = WFTaskFactory::create_redis_task(url, RETRY_MAX, std::move(set_cb));
	auto *B = WFTaskFactory::create_redis_task(url, RETRY_MAX, std::move(get_cb));
	auto *C = WFTaskFactory::create_redis_task(url, RETRY_MAX, std::move(del_cb));
	auto& flow = *A > B > C;

	A->get_req()->set_request("SET", {"testkey", "testvalue"});
	B->get_req()->set_request("GET", {"testkey"});
	C->get_req()->set_request("DEL", {"testkey"});
	flow.set_callback([&mutex, &cond, &done](const SeriesWork *series) {
		mutex.lock();
		done = true;
		mutex.unlock();
		cond.notify_one();
	});

	flow.start();
}

TEST(redis_unittest, WFRedisTask1)
{
	std::mutex mutex;
	std::condition_variable cond;
	bool done = false;
	WFRedisServer server(__redis_process);
	EXPECT_TRUE(server.start("127.0.0.1", 6677) == 0) << "server start failed";

	test_client("redis://:testpass@127.0.0.1:6677/6", mutex, cond, done);
	std::unique_lock<std::mutex> lock(mutex);
	while (!done)
		cond.wait(lock);

	lock.unlock();
	server.stop();
}


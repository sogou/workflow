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

#include <mutex>
#include <condition_variable>
#include <chrono>
#include <gtest/gtest.h>
#include "workflow/WFTaskFactory.h"
#include "workflow/WFMySQLServer.h"

#define RETRY_MAX  3

static void __mysql_process(WFMySQLTask *task)
{
	//auto *req = task->get_req();
	auto *resp = task->get_resp();

	resp->set_ok_packet();
}

static void test_client(const char *url, const char *sql, std::mutex& mutex, std::condition_variable& cond, bool& done)
{
	auto *task = WFTaskFactory::create_mysql_task(url, RETRY_MAX, [&mutex, &cond, &done](WFMySQLTask *task) {
		auto state = task->get_state();
		EXPECT_EQ(state, WFT_STATE_SUCCESS);
		mutex.lock();
		done = true;
		mutex.unlock();
		cond.notify_one();
	});

	task->get_req()->set_query(sql);
	task->start();
}

TEST(mysql_unittest, WFMySQLTask1)
{
	std::mutex mutex;
	std::condition_variable cond;
	bool done = false;
	WFMySQLServer server(__mysql_process);
	EXPECT_TRUE(server.start("127.0.0.1", 8899) == 0) << "server start failed";

	test_client("mysql://testuser:testpass@127.0.0.1:8899/testdb",
				"select * from testtable limit 3", mutex, cond, done);
	std::unique_lock<std::mutex> lock(mutex);
	while (!done)
		cond.wait(lock);

	lock.unlock();
	server.stop();
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L

#include <openssl/ssl.h>
int main(int argc, char* argv[])
{
	OPENSSL_init_ssl(0, 0);
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

#endif


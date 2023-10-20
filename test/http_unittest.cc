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
#include "workflow/WFOperator.h"
#include "workflow/WFHttpServer.h"
#include "workflow/HttpUtil.h"

#define RETRY_MAX  3

TEST(http_unittest, WFHttpTask1)
{
	std::mutex mutex;
	std::condition_variable cond;
	bool done = false;
	auto *task = WFTaskFactory::create_http_task("http://github.com", 0, RETRY_MAX, [&mutex, &cond, &done](WFHttpTask *task) {
		auto state = task->get_state();

		//EXPECT_EQ(state, WFT_STATE_SUCCESS);
		if (state == WFT_STATE_SUCCESS)
		{
			auto code = atoi(task->get_resp()->get_status_code());
			EXPECT_TRUE(code == HttpStatusOK ||
						code == HttpStatusMovedPermanently ||
						code == HttpStatusFound ||
						code == HttpStatusSeeOther ||
						code == HttpStatusTemporaryRedirect ||
						code == HttpStatusPermanentRedirect);
		}

		mutex.lock();
		done = true;
		mutex.unlock();
		cond.notify_one();
	});
	task->start();

	std::unique_lock<std::mutex> lock(mutex);
	while (!done)
		cond.wait(lock);

	lock.unlock();
}

TEST(http_unittest, WFHttpTask2)
{
	std::mutex mutex;
	std::condition_variable cond;
	bool done = false;
	auto *task = WFTaskFactory::create_http_task("http://github.com", 1, RETRY_MAX, [&mutex, &cond, &done](WFHttpTask *task) {
		auto state = task->get_state();

		//EXPECT_EQ(state, WFT_STATE_SUCCESS);
		if (state == WFT_STATE_SUCCESS)
		{
			auto code = atoi(task->get_resp()->get_status_code());
			EXPECT_TRUE(code == HttpStatusOK ||
						code == HttpStatusMovedPermanently ||
						code == HttpStatusFound ||
						code == HttpStatusSeeOther ||
						code == HttpStatusTemporaryRedirect ||
						code == HttpStatusPermanentRedirect);
		}

		mutex.lock();
		done = true;
		mutex.unlock();
		cond.notify_one();
	});
	task->start();

	std::unique_lock<std::mutex> lock(mutex);
	while (!done)
		cond.wait(lock);

	lock.unlock();
}


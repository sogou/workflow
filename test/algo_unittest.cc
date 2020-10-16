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
#include "workflow/WFAlgoTaskFactory.h"

static void __arr_init(int *arr, int n)
{
	srand(time(NULL));
	for (int i = 0; i < n; i++)
		arr[i] = rand() % 65536;
}

static void __arr_check(int *arr, int n)
{
	for (int i = 1; i < n; i++)
		EXPECT_LE(arr[i - 1], arr[i]);
}

TEST(algo_unittest, sort)
{
	static constexpr int n = 100000;
	int *arr = new int[n];
	__arr_init(arr, n);

	std::mutex mutex;
	std::condition_variable cond;
	bool done = false;
	auto *task = WFAlgoTaskFactory::create_sort_task("sort", arr, arr + n, [&mutex, &cond, &done](WFSortTask<int> *task) {
		int *first = task->get_input()->first;
		int *last = task->get_input()->last;
		__arr_check(first, last - first);
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

	delete []arr;
}

TEST(algo_unittest, parallel_sort)
{
	static constexpr int n = 100000;
	int *arr = new int[n];
	__arr_init(arr, n);

	std::mutex mutex;
	std::condition_variable cond;
	bool done = false;
	auto *task = WFAlgoTaskFactory::create_psort_task("psort", arr, arr + n, [&mutex, &cond, &done](WFSortTask<int> *task) {
		int *first = task->get_input()->first;
		int *last = task->get_input()->last;
		__arr_check(first, last - first);
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

	delete []arr;
}


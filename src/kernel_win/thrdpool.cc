/*
  Copyright (c) 2019 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Authors: Xie Han (xiehan@sogou-inc.com)
           Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <thread>
#include <mutex>
#include <set>
#include <condition_variable>
#include "list.h"
#include "thrdpool.h"

struct __thrdpool
{
	struct list_head task_queue;
	std::mutex mutex;
	std::condition_variable cond;
	std::vector<std::thread *> threads;
	std::set<std::thread::id> threadids;
	bool terminate;
};

struct __thrdpool_task_entry
{
	struct list_head list;
	struct thrdpool_task task;
};

static void __thrdpool_routine(thrdpool_t *pool)
{
	struct list_head **pos = &pool->task_queue.next;
	__thrdpool_task_entry *entry;
	std::unique_lock<std::mutex> lock(pool->mutex, std::defer_lock);

	while (1)
	{
		lock.lock();
		while (!pool->terminate && list_empty(&pool->task_queue))
			pool->cond.wait(lock);

		if (pool->terminate)
			break;

		entry = list_entry(*pos, __thrdpool_task_entry, list);
		list_del(*pos);
		lock.unlock();

		entry->task.routine(entry->task.context);
		delete entry;
	}
}

static void __thrdpool_terminate(thrdpool_t *pool)
{
	std::unique_lock<std::mutex> lock(pool->mutex);

	pool->terminate = true;
	pool->cond.notify_all();
	for (size_t i = 0; i < pool->threads.size(); i++)
	{
		std::thread *th = pool->threads[i];
		lock.unlock();
		th->join();
		lock.lock();
	}
}

static int __thrdpool_create_threads(size_t nthreads, size_t stacksize,
									 thrdpool_t *pool)
{
	// not support stacksize;
	for (size_t i = 0; i < nthreads; i++)
	{
		auto *th = new std::thread(__thrdpool_routine, pool);

		pool->threads.push_back(th);
		pool->threadids.emplace(th->get_id());
	}

	return 0;
}

thrdpool_t *thrdpool_create(size_t nthreads, size_t stacksize)
{
	thrdpool_t *pool = new __thrdpool;

	INIT_LIST_HEAD(&pool->task_queue);
	pool->threads.clear();
	pool->terminate = false;
	if (__thrdpool_create_threads(nthreads, stacksize, pool) >= 0)
		return pool;

	delete pool;
	return NULL;
}

void __thrdpool_schedule(const struct thrdpool_task *task, void *buf,
						 thrdpool_t *pool)
{
	__thrdpool_task_entry *entry = (__thrdpool_task_entry *)buf;
	entry->task = *task;
	std::lock_guard<std::mutex> lock(pool->mutex);

	list_add_tail(&entry->list, &pool->task_queue);
	pool->cond.notify_one();
}

int thrdpool_schedule(const struct thrdpool_task *task, thrdpool_t *pool)
{
	__thrdpool_schedule(task, new __thrdpool_task_entry, pool);
	return 0;
}

int thrdpool_increase(thrdpool_t *pool)
{
	std::lock_guard<std::mutex> lock(pool->mutex);
	auto *th = new std::thread(__thrdpool_routine, pool);

	pool->threads.push_back(th);
	pool->threadids.emplace(th->get_id());
	return 0;
}

int thrdpool_in_pool(thrdpool_t *pool)
{
	std::lock_guard<std::mutex> lock(pool->mutex);
	return pool->threadids.count(std::this_thread::get_id()) > 0;
}

void thrdpool_destroy(void (*pending)(const struct thrdpool_task *),
					  thrdpool_t *pool)
{
	__thrdpool_task_entry *entry;
	struct list_head *pos, *tmp;

	__thrdpool_terminate(pool);
	list_for_each_safe(pos, tmp, &pool->task_queue)
	{
		entry = list_entry(pos, __thrdpool_task_entry, list);
		list_del(pos);
		if (pending)
			pending(&entry->task);

		delete entry;
	}

	for (auto& th : pool->threads)
		delete th;

	delete pool;
}


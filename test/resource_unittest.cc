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
#include <gtest/gtest.h>
#include "workflow/WFTask.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/WFResourcePool.h"
#include "workflow/WFFacilities.h"

TEST(resource_unittest, resource_pool)
{
	int res_concurrency = 3;
	int task_concurrency = 10;
	const char *words[3] = {"workflow", "srpc", "pyworkflow"};
	WFResourcePool res_pool((void * const*)words, res_concurrency);
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


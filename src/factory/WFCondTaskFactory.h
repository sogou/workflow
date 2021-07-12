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

#ifndef _WFCONDTASKFACTORY_H_
#define _WFCONDTASKFACTORY_H_

#include <mutex>
#include <time.h>
#include <functional>
#include <string>
#include "list.h"
#include "WFTask.h"
#include "WFTaskFactory.h"
#include "WFGlobal.h"
#include "WFCondition.h"

class WFSemaphore
{
public:
	WFConditional *get(SubTask *task, void **psem);
	void post(void *sem);

private:
	std::mutex mutex;
	struct list_head wait_list;

	struct entry
	{
		struct list_head list;
		WFConditional *ptr;
	};

public:
	WFSemaphore(void **sems, int n)
	{
		INIT_LIST_HEAD(&this->wait_list);
		this->value = n;
		this->index = n;
		this->sems = sems;
	}

	virtual ~WFSemaphore() { }

private:
	std::atomic<int> value;
	std::atomic<int> index;

protected:
	void **sems;
};

class WFCondTaskFactory
{
public:
	// use condition by name
	static void signal_by_name(const std::string& name, void *msg);

	static void broadcast_by_name(const std::string& name, void *msg);

	static WFWaitTask *create_wait_task(const std::string& name,
										wait_callback_t callback);

	static WFWaitTask *create_timedwait_task(const std::string& name,
											 const struct timespec *timeout,
											 wait_callback_t callback);

	static WFWaitTask *create_swait_task(const std::string& name,
										 wait_callback_t callback);

	// use condition by ptr
	static WFWaitTask *create_wait_task(WFCondition *cond,
										wait_callback_t callback);

	static WFWaitTask *create_timedwait_task(WFCondition *cond,
											 const struct timespec *timeout,
											 wait_callback_t callback);

	static WFWaitTask *create_swait_task(WFCondition *cond,
										 wait_callback_t callback);

};

#endif


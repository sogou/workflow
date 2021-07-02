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

#ifndef _WFSEMAPHORE_H_
#define _WFSEMAPHORE_H_

#include <mutex>
#include <time.h>
#include <functional>
#include <atomic>
#include "list.h"
#include "WFTask.h"
#include "WFTaskFactory.h"
#include "WFGlobal.h"

using WFWaitTask = WFMailboxTask;
using wait_callback_t = mailbox_callback_t;

class WFSemaphore
{
public:
	bool get(WFConditional *cond);
	void post(void *msg);

public:
	std::mutex mutex;
	struct list_head wait_list;

private:
	struct entry
	{
		struct list_head list;
		WFConditional *ptr;
	};

public:
	WFSemaphore(int value, void **resources)
	{
		if (value <= 0)
			value = 1;

		INIT_LIST_HEAD(&this->wait_list);
		this->concurrency = value;
		this->total = value;
		this->index = value;
		this->resources = resources;
	}

	virtual ~WFSemaphore() { }

private:
	std::atomic<int> concurrency;
	int total;
	int index;

protected:
	void **resources;
};

class WFCondition
{
public:
	void signal(void *msg);
	void broadcast(void *msg);

public:
	WFCondition() { INIT_LIST_HEAD(&this->wait_list); }
	virtual ~WFCondition() { }

public:
	std::mutex mutex;
	struct list_head wait_list;
};

#include "WFCondition.inl"

#endif


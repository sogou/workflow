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

#ifndef _WFCONDITION_H_
#define _WFCONDITION_H_

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

class WFCondition
{
public:
	void signal(void *msg);
	void broadcast(void *msg);
	// 1: existed; 0: should get; -1: should wait;
	int get(void **pmsg);
	WFWaitTask *get_wait_task(wait_callback_t callback);

public:
	std::atomic<int> *ref;
	std::mutex *mutex;
	struct list_head get_list;
	struct list_head wait_list;

public:
	class BaseResource
	{
	public:
		virtual void *get() = 0;
		virtual void set() { this->ptr->empty = 0; }
		void clear() { this->ptr->empty = 1; }

	private:
		WFCondition *ptr;
		friend WFCondition;
	};

private:
	BaseResource *res;
	int empty;

public:
	WFCondition(BaseResource *res)
	{
		this->empty = 1;
		this->res = res;
		this->res->ptr = this;
		this->mutex = new std::mutex;
		this->ref = new std::atomic<int>(1);
		INIT_LIST_HEAD(&this->get_list);
		INIT_LIST_HEAD(&this->wait_list);
	}

	WFCondition()
	{
		this->empty = 0;
		this->res = NULL;
		this->mutex = new std::mutex;
		this->ref = new std::atomic<int>(1);
		INIT_LIST_HEAD(&this->get_list);
		INIT_LIST_HEAD(&this->wait_list);
	}

	virtual ~WFCondition();
};

#endif


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

#include <mutex>
#include <atomic>
#include "list.h"
#include "WFTask.h"
#include "WFTaskFactory.h"

class WFCondWaitTask : public WFMailboxTask
{
public:
	void set_state(int state) { this->state = state; }
	void set_error(int error) { this->error = error; }
	virtual void count();

private:
	void *msg;

public:
	WFCondWaitTask(mailbox_callback_t&& cb) :
		WFMailboxTask(&this->msg, 1, std::move(cb))
	{
		this->list.next = NULL;
	}

	virtual ~WFCondWaitTask() { }

public:
	struct list_head list;
};

class __WFWaitTimerTask;

class WFTimedWaitTask : public WFCondWaitTask
{
public:
	void set_timer(__WFWaitTimerTask *timer) { this->timer = timer; }
	void clear_timer_waiter();

protected:
	virtual void dispatch();

private:
	__WFWaitTimerTask *timer;

public:
	WFTimedWaitTask(mailbox_callback_t&& cb) :
		WFCondWaitTask(std::move(cb))
	{
		this->timer = NULL;
	}

	virtual ~WFTimedWaitTask();
};

class __WFWaitTimerTask : public __WFTimerTask
{
public:
	void clear_wait_task() // must called within this mutex
	{
		this->wait_task = NULL;
	}

	__WFWaitTimerTask(WFTimedWaitTask *wait_task, const struct timespec *value,
					  std::mutex *mutex, std::atomic<int> *ref,
					  CommScheduler *scheduler) :
		__WFTimerTask(value, scheduler, nullptr)
	{
		this->ref = ref;
		++*this->ref;
		this->mutex = mutex;
		this->wait_task = wait_task;
	}

	virtual ~__WFWaitTimerTask();

protected:
	virtual SubTask *done();

private:
	std::mutex *mutex;
	std::atomic<int> *ref;
	WFTimedWaitTask *wait_task;
};

class WFSwitchWaitTask : public WFCondWaitTask
{
public:
	WFSwitchWaitTask(mailbox_callback_t&& cb) :
		WFCondWaitTask(std::move(cb))
	{ }

protected:
	SubTask *done();
};


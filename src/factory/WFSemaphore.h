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
          Liu Kai (liukaidx@sogou-inc.com)
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

class WFSemaphore
{
public:
	WFMailboxTask *acquire(std::function<void (WFMailboxTask *)> cb);
	void release(void *msg);

public:
	std::mutex mutex;
	struct list_head waiter_list;
	
public:
	WFSemaphore(int value)
	{
		INIT_LIST_HEAD(&this->waiter_list);
		this->concurrency = value;
	}

private:
	std::atomic<int> concurrency;
};

class WFCondition : public WFSemaphore
{	
public:
	void signal(void *msg);
	void broadcast(void *msg);

public:
	WFCondition() : WFSemaphore(1) { }
	WFCondition(int value) : WFSemaphore(value) { }
	~WFCondition() { }
};

class WFSemaphoreTask : public WFMailboxTask
{
public:
	WFSemaphoreTask(std::function<void (WFMailboxTask *)>&& cb) :
		WFMailboxTask(&this->msg, 1, std::move(cb))
	{
		this->node.list.next = NULL;
		this->node.ptr = this;
	}

	virtual ~WFSemaphoreTask() { }

public:
	struct entry
	{
		struct list_head list;
		WFSemaphoreTask *ptr;
	} node;

private:
	void *msg;
};

class WFTimedWaitTask;

class WFWaitTask : public WFSemaphoreTask
{
public:
	void set_timer(WFTimedWaitTask *timer) { this->timer = timer; }
	void clear_timer_waiter();
	void set_error(int error) { this->error = error; }

protected:
	void dispatch();

private:
	WFTimedWaitTask *timer;

public:
	WFWaitTask(std::function<void (WFMailboxTask *)>&& cb) :
		WFSemaphoreTask(std::move(cb))
	{
		this->timer = NULL;
	}

	virtual ~WFWaitTask() { }
};

class WFTimedWaitTask : public __WFTimerTask
{
public:
	WFTimedWaitTask(WFWaitTask *wait_task, std::mutex *mutex,
					const struct timespec *value,
					CommScheduler *scheduler,
					std::function<void (WFTimerTask *)> cb) :
		__WFTimerTask(value, scheduler, std::move(cb))
	{
		this->mutex = mutex;
		this->wait_task = wait_task;
	}

	void clear_wait_task() // must called within this mutex
	{
		this->wait_task = NULL;
	}

protected:
	virtual SubTask *done();

private:
	std::mutex *mutex;
	WFWaitTask *wait_task;
};

class WFSwitchWaitTask : public WFWaitTask
{
public:
	WFSwitchWaitTask(std::function<void (WFMailboxTask *)>&& cb) :
			WFWaitTask(std::move(cb))
	{ }

protected:
	SubTask *done()
	{
		SeriesWork *series = series_of(this);

		WFTimerTask *switch_task = WFTaskFactory::create_timer_task(0,
			[this](WFTimerTask *task) {
				if (this->callback)
					this->callback(this);
				delete this;
		});
		series->push_front(switch_task);

		return series->pop();
	}
};

#endif


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
          Xie Han (xiehan@sogou-inc.com)
          Liu Kai (liukaidx@sogou-inc.com)
*/

#include "list.h"
#include "WFTask.h"
#include "WFTaskFactory.h"

class WFSemaphoreTask : public WFWaitTask
{
public:
	WFSemaphoreTask(std::function<void (WFWaitTask *)>&& cb) :
		WFWaitTask(&this->msg, 1, std::move(cb))
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

class WFCondWaitTask : public WFSemaphoreTask
{
public:
	void set_timer(WFTimedWaitTask *timer) { this->timer = timer; }
	void clear_timer_waiter();
	void set_error(int error) { this->error = error; }

protected:
	void dispatch();
	SubTask *done();

private:
	WFTimedWaitTask *timer;

public:
	WFCondWaitTask(std::function<void (WFMailboxTask *)>&& cb) :
		WFSemaphoreTask(std::move(cb))
	{
		this->timer = NULL;
	}

	virtual ~WFCondWaitTask() { }
};

class WFTimedWaitTask : public __WFTimerTask
{
public:
	WFTimedWaitTask(WFCondWaitTask *wait_task, std::mutex *mutex,
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
	WFCondWaitTask *wait_task;
};


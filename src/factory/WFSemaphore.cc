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

#include <mutex>
#include <time.h>
#include <functional>
#include "list.h"
#include "WFTask.h"
#include "WFTaskFactory.h"
#include "WFSemaphore.h"

/////////////// Semaphore Impl ///////////////

WFMailboxTask *WFSemaphore::acquire(std::function<void (WFMailboxTask *)> cb)
{
	WFSemaphoreTask *task = new WFSemaphoreTask(std::move(cb));

	if (--this->concurrency >= 0)
	{
		task->count();
	}
	else
	{
		this->mutex.lock();
		list_add_tail(&task->list, &this->waiter_list);
		this->mutex.unlock();
	}

	return task;
}

void WFSemaphore::release(void *msg)
{
	WFSemaphoreTask *task;
	struct list_head *pos;

	this->mutex.lock();

	if (++this->concurrency <= 0)// && !list_empty(&this->waiter_list))
	{
		pos = this->waiter_list.next;
		task = list_entry(pos, WFSemaphoreTask, list);
		list_del(pos);
		task->send(msg);
	}

	this->mutex.unlock();
}

/////////////// Wait tasks Impl ///////////////

void WFWaitTask::dispatch()
{
	if (this->timer)
		timer->dispatch();
	
	this->WFMailboxTask::count();
}

void WFWaitTask::clear_timer_waiter()
{
	if (this->timer)
		timer->clear_wait_task();
}

SubTask *WFTimedWaitTask::done()
{
	this->mutex->lock();
	if (this->wait_task && this->wait_task->list.next)
	{
		list_del(&this->wait_task->list);
		this->wait_task->set_error(ETIMEDOUT);
		this->wait_task->count();
		this->wait_task = NULL;
	}
	this->mutex->unlock();

	delete this;
	return NULL;
}

/////////////// Condition Impl ///////////////

void WFCondition::signal(void *msg)
{
	WFWaitTask *task;
	struct list_head *pos;

	this->mutex.lock();

	if (!list_empty(&this->waiter_list))
	{
		pos = this->waiter_list.next;
		task = list_entry(pos, WFWaitTask, list);
		list_del(pos);
		task->clear_timer_waiter();
		task->send(msg);
	}

	this->mutex.unlock();
}

void WFCondition::broadcast(void *msg)
{
	WFWaitTask *task;
	struct list_head *pos, *tmp;

	this->mutex.lock();
	if (!list_empty(&this->waiter_list))
	{
		list_for_each_safe(pos, tmp, &this->waiter_list)
		{
			task = list_entry(pos, WFWaitTask, list);
			list_del(pos);
			task->send(msg);
		}
	}
	this->mutex.unlock();
}


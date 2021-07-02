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
#include <time.h>
#include <functional>
#include "list.h"
#include "WFTask.h"
#include "WFTaskFactory.h"
#include "WFCondition.h"

/////////////// Semaphore Impl ///////////////

bool WFSemaphore::get(WFConditional *cond)
{
	this->mutex.lock();
	if (--this->concurrency >= 0)
	{
		cond->signal(this->resources[--this->index]);
		this->mutex.unlock();
		return true;
	}

	struct WFSemaphore::entry *entry;
	entry = new WFSemaphore::entry;
	entry->ptr = cond;
	entry->list.next = NULL;

	list_add_tail(&entry->list, &this->wait_list);
	this->mutex.unlock();

	return false;
}

void WFSemaphore::post(void *msg)
{
	struct WFSemaphore::entry *entry;
	WFConditional *cond = NULL;
	struct list_head *pos;

	this->mutex.lock();

	if (++this->concurrency <= 0)
	{
		pos = this->wait_list.next;
		entry = list_entry(pos, struct WFSemaphore::entry, list);
		cond = entry->ptr;
		list_del(pos);
		delete entry;
	}
	else
		this->resources[this->index++] = msg;

	this->mutex.unlock();
	if (cond)
		cond->signal(msg);
}

/////////////// Wait tasks Impl ///////////////

void WFCondWaitTask::dispatch()
{
	if (this->timer)
		timer->dispatch();

	this->WFWaitTask::count();
}

SubTask *WFCondWaitTask::done()
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

void WFCondWaitTask::clear_timer_waiter()
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
	WFCondWaitTask *task = NULL;
	struct list_head *pos;

	this->mutex.lock();
	if (!list_empty(&this->wait_list))
	{
		pos = this->wait_list.next;
		task = list_entry(pos, WFCondWaitTask, list);
		list_del(pos);
		task->clear_timer_waiter();
	}

	this->mutex.unlock();
	if (task)
		task->send(msg);
}

void WFCondition::broadcast(void *msg)
{
	WFCondWaitTask *task;
	struct list_head *pos, *tmp;
	LIST_HEAD(tmp_list);

	this->mutex.lock();
	if (!list_empty(&this->wait_list))
	{
		list_for_each_safe(pos, tmp, &this->wait_list)
		{
			list_move_tail(pos, &tmp_list);
		}
	}

	this->mutex.unlock();
	while (!list_empty(&tmp_list))
	{
		task = list_entry(tmp_list.next, WFCondWaitTask, list);
		list_del(&task->list);
		task->send(msg);
	}
}


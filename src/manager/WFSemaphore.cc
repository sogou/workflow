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

#include <mutex>
#include <time.h>
#include <functional>
#include "list.h"
#include "WFTask.h"
#include "WFTaskFactory.h"
#include "WFSemaphore.h"

/////////////// Semaphore Impl ///////////////

bool WFSemaphore::get()
{
	if (--this->concurrency >= 0)
		return true;

	WFSemaphoreTask *task = new WFSemaphoreTask(nullptr);

	this->mutex.lock();
	list_add_tail(&task->node.list, &this->get_list);
	this->mutex.unlock();

	return false;
}

WFWaitTask *WFSemaphore::create_wait_task(std::function<void (WFWaitTask *)> cb)
{
	WFSemaphoreTask *task = NULL;
	struct list_head *pos;
	struct WFSemaphoreTask::entry *node;

	this->mutex.lock();
	if (!list_empty(&this->get_list))
	{
		pos = this->get_list.next;
		list_move_tail(pos, &this->wait_list);
		node = list_entry(pos, struct WFSemaphoreTask::entry, list);
		task = node->ptr;
		task->set_callback(std::move(cb));
	}

	this->mutex.unlock();
	return task;
}

void WFSemaphore::post(void *msg)
{
	WFSemaphoreTask *task = NULL;
	struct list_head *pos;
	struct WFSemaphoreTask::entry *node;

	this->mutex.lock();

	if (++this->concurrency <= 0)
	{
		if (!list_empty(&this->wait_list))
			pos = this->wait_list.next;
		else
			pos = this->get_list.next;
		node = list_entry(pos, struct WFSemaphoreTask::entry, list);
		task = node->ptr;
		list_del(pos);
	}

	this->mutex.unlock();
	if (task)
		task->send(msg);
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
	if (this->wait_task && this->wait_task->node.list.next)
	{
		list_del(&this->wait_task->node.list);
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
	struct WFSemaphoreTask::entry *node;

	this->mutex.lock();
	if (!list_empty(&this->wait_list))
	{
		pos = this->wait_list.next;
		node = list_entry(pos, struct WFSemaphoreTask::entry, list);
		task = (WFCondWaitTask *)node->ptr;
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
	struct WFSemaphoreTask::entry *node;
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
		node = list_entry(tmp_list.next, struct WFSemaphoreTask::entry, list);
		task = (WFCondWaitTask *)node->ptr;
		list_del(&node->list);
		task->send(msg);
	}
}


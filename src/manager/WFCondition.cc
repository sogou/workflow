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

#include <time.h>
#include "WFTask.h"
#include "WFTaskFactory.h"
#include "WFGlobal.h"
#include "WFCondition.h"

class WFTimedWaitTask;

class WFWaitTask : public WFCounterTask
{
public:
	void set_timer(WFTimedWaitTask *timer) { this->timer = timer; }
	void clear_timer_waiter();

	struct task_entry
	{
		struct list_head list;
		WFWaitTask *ptr;
	} entry;

protected:
	virtual void dispatch();
	virtual SubTask *done();

private:
	WFTimedWaitTask *timer;

public:
	WFWaitTask(std::function<void (WFCounterTask *)>&& cb) :
		WFCounterTask(1, std::move(cb))
	{
		this->timer = NULL;
		this->entry.list.next = NULL;
		this->entry.ptr = this;
	}
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

	void clear_wait_task();

protected:
	virtual SubTask *done();

private:
	std::mutex *mutex;
	WFWaitTask *wait_task;
};

void WFWaitTask::dispatch()
{
	if (this->timer)
		timer->dispatch();
	
	this->WFCounterTask::count();
}

SubTask *WFWaitTask::done()
{
	SeriesWork *series = series_of(this);

	// TODO: data move

	WFTimerTask *switch_task = WFTaskFactory::create_timer_task(0,
		[this](WFTimerTask *task) {
			if (this->callback)
				this->callback(this);
			delete this;
	});
	series->push_front(switch_task);

	return series->pop();
}

void WFWaitTask::clear_timer_waiter()
{
	if (this->timer)
		timer->clear_wait_task();
}

SubTask *WFTimedWaitTask::done()
{
	WFWaitTask *tmp = NULL;

	this->mutex->lock();
	if (this->wait_task && this->wait_task->entry.list.next)
	{
		list_del(&this->wait_task->entry.list);
		tmp = this->wait_task;
		this->wait_task = NULL;
	}
	this->mutex->unlock();

	if (tmp)
		tmp->count();

	SeriesWork *series = series_of(this);
	
	if (this->callback)
		this->callback(this);

	delete this;
	return series->pop();
}

void WFTimedWaitTask::clear_wait_task()
{
	this->mutex->lock();
	this->wait_task = NULL;
	this->mutex->unlock();
}

WFCounterTask *WFCondition::create_wait_task(counter_callback_t cb)
{
	WFWaitTask *task = new WFWaitTask(std::move(cb));

	this->mutex.lock();
	list_add_tail(&task->entry.list, &this->waiter_list);
	this->mutex.unlock();

	return task;
}

WFCounterTask *WFCondition::create_timedwait_task(const struct timespec *abstime,
												  counter_callback_t cb)
{
	WFWaitTask *waiter = new WFWaitTask(std::move(cb));
	WFTimedWaitTask *task = new WFTimedWaitTask(waiter, &this->mutex, abstime,
												WFGlobal::get_scheduler(),
												nullptr);
	waiter->set_timer(task);

	this->mutex.lock();
	list_add_tail(&waiter->entry.list, &this->waiter_list);
	this->mutex.unlock();

	return waiter;
}

void WFCondition::signal()
{
	WFWaitTask *task = NULL;
	struct list_head *pos;
	struct WFWaitTask::task_entry *entry;

	this->mutex.lock();

	if (!list_empty(&this->waiter_list))
	{
		pos = this->waiter_list.next;
		entry = list_entry(pos, struct WFWaitTask::task_entry, list);
		task = entry->ptr;
		list_del(pos);
		task->clear_timer_waiter();
	}

	this->mutex.unlock();

	if (task)
		task->count();
}

void WFCondition::broadcast()
{
	WFWaitTask *task;
	struct list_head *pos, *tmp;
	struct WFWaitTask::task_entry *entry;
	LIST_HEAD(tmp_list);

	this->mutex.lock();
	if (!list_empty(&this->waiter_list))
	{
		list_for_each_safe(pos, tmp, &this->waiter_list)
		{
			entry = list_entry(pos, struct WFWaitTask::task_entry, list);
			list_move_tail(pos, &tmp_list);
		}
	}
	this->mutex.unlock();

	while (!list_empty(&tmp_list))
	{
		entry = list_entry(tmp_list.next, struct WFWaitTask::task_entry, list);
		task = entry->ptr;
		list_del(&entry->list);
		task->count();
	}
}


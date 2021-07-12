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
#include "WFCondTask.h"
#include "WFTaskFactory.h"

void WFCondWaitTask::count()
{
	if (--this->value == 0)
	{
		if (this->state == WFT_STATE_UNDEFINED)
			this->state = WFT_STATE_SUCCESS;
		this->subtask_done();
	}
}

void WFTimedWaitTask::dispatch()
{
	if (this->timer)
		timer->dispatch();

	this->WFMailboxTask::count();
}

WFTimedWaitTask::~WFTimedWaitTask()
{
	delete this->timer;
}

SubTask *WFSwitchWaitTask::done()
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

void WFTimedWaitTask::clear_timer_waiter()
{
	if (this->timer)
		timer->clear_wait_task();
}

SubTask *__WFWaitTimerTask::done()
{
	WFTimedWaitTask *waiter = NULL;

	this->mutex->lock();
	if (this->wait_task)
	{
		list_del(&this->wait_task->list);
		this->wait_task->set_state(WFT_STATE_SYS_ERROR);
		this->wait_task->set_error(ETIMEDOUT);
		waiter = this->wait_task;
		waiter->set_timer(NULL);
	}
	this->mutex->unlock();

	if (waiter)
		waiter->count();
	delete this;
	return NULL;
}

__WFWaitTimerTask::~__WFWaitTimerTask()
{
	if (--*this->ref == 0)
	{
		delete this->mutex;
		delete this->ref;
	}
}


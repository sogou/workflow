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
#include "list.h"
#include "WFTask.h"
#include "WFCondTask.h"
#include "WFCondition.h"

int WFCondition::get(void **pmsg)
{
//	if (this->res == NULL)
//		return -2;
	int ret;

	this->mutex->lock();
	if (this->empty == 1)
	{
		*pmsg = this->res->get();
		ret = 1;
	}
	else if (--this->empty == 0)
	{
		ret = 0;
	}
	else
	{
		WFCondWaitTask *task = new WFCondWaitTask(nullptr);
		list_add_tail(&task->list, &this->get_list);
		ret = -1;
	}
	this->mutex->unlock();

	return ret;
}

WFWaitTask *WFCondition::get_wait_task(wait_callback_t callback)
{
	WFCondWaitTask *task = NULL;
 	struct list_head *pos;

 	this->mutex->lock();
 	if (!list_empty(&this->get_list))
 	{
 		pos = this->get_list.next;
 		list_move_tail(pos, &this->wait_list);
 		task = list_entry(pos, WFCondWaitTask, list);
 		task->set_callback(std::move(callback));
 	}

 	this->mutex->unlock();
 	return task;
}

void WFCondition::signal(void *msg)
{
	WFCondWaitTask *task = NULL;

	this->mutex->lock();

	if (!list_empty(&this->wait_list))
		task = list_entry(this->wait_list.next, WFCondWaitTask, list);
	else if (!list_empty(&this->get_list))
		task = list_entry(this->get_list.next, WFCondWaitTask, list);

	if (task)
	{
		list_del(&task->list);
		task->clear_locked();
	}

	this->mutex->unlock();
	if (task)
		task->send(msg);
}

void WFCondition::broadcast(void *msg)
{
	WFCondWaitTask *task;
	struct list_head *pos, *tmp;
	LIST_HEAD(tmp_list);

	this->mutex->lock();
	if (!list_empty(&this->wait_list))
	{
		list_for_each_safe(pos, tmp, &this->wait_list)
		{
			list_move_tail(pos, &tmp_list);
			task = list_entry(pos, WFCondWaitTask, list);
			task->clear_locked();
		}
	}

	if (!list_empty(&this->get_list))
	{
		list_for_each_safe(pos, tmp, &this->get_list)
		{
			list_move_tail(pos, &tmp_list);
			task = list_entry(pos, WFCondWaitTask, list);
			task->clear_locked();
		}
	}

	this->mutex->unlock();
	while (!list_empty(&tmp_list))
	{
		task = list_entry(tmp_list.next, WFCondWaitTask, list);
		list_del(&task->list);
		task->send(msg);
	}
}

WFCondition::~WFCondition()
{
	this->broadcast(NULL);

	if (--*this->ref == 0)
	{
		delete this->mutex;
		delete this->ref;
	}
}


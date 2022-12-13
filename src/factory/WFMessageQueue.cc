/*
  Copyright (c) 2022 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Authors: Xie Han (xiehan@sogou-inc.com)
*/

#include "list.h"
#include "WFTask.h"
#include "WFMessageQueue.h"

class __MQConditional : public WFConditional
{
public:
	struct list_head list;
	struct WFMessageQueue::Data *data;

public:
	virtual void dispatch();
	virtual void signal(void *msg) { }

public:
	__MQConditional(SubTask *task, void **msgbuf,
					struct WFMessageQueue::Data *data) :
		WFConditional(task, msgbuf)
	{
		this->data = data;
	}

	__MQConditional(SubTask *task,
					struct WFMessageQueue::Data *data) :
		WFConditional(task)
	{
		this->data = data;
	}
};

void __MQConditional::dispatch()
{
	struct WFMessageQueue::Data *data = this->data;

	data->mutex.lock();
	if (!list_empty(&data->msg_list))
		this->WFConditional::signal(data->pop());
	else
		list_add_tail(&this->list, &data->wait_list);

	data->mutex.unlock();
	this->WFConditional::dispatch();
}

WFConditional *WFMessageQueue::get(SubTask *task, void **msgbuf)
{
	return new __MQConditional(task, msgbuf, &this->data);
}

WFConditional *WFMessageQueue::get(SubTask *task)
{
	return new __MQConditional(task, &this->data);
}

void WFMessageQueue::post(void *msg)
{
	struct WFMessageQueue::Data *data = &this->data;
	WFConditional *cond;

	data->mutex.lock();
	if (!list_empty(&data->wait_list))
	{
		cond = list_entry(data->wait_list.next, __MQConditional, list);
		list_del(data->wait_list.next);
	}
	else
	{
		cond = NULL;
		this->push(msg);
	}

	data->mutex.unlock();
	if (cond)
		cond->WFConditional::signal(msg);
}


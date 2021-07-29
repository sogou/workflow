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
*/

#include <string.h>
#include "list.h"
#include "WFTask.h"
#include "WFResourcePool.h"

class __WFConditional : public WFConditional
{
public:
	struct list_head list;
	struct WFResourcePool::Data *data;

public:
	virtual void dispatch();
	virtual void signal(void *res) { }

public:
	__WFConditional(SubTask *task, void **resbuf,
					struct WFResourcePool::Data *data) :
		WFConditional(task, resbuf)
	{
		this->data = data;
	}
};

void __WFConditional::dispatch()
{
	struct WFResourcePool::Data *data = this->data;

	data->mutex.lock();
	if (--data->value >= 0)
		this->WFConditional::signal(data->pop());
	else
		list_add_tail(&this->list, &data->wait_list);

	data->mutex.unlock();
	this->WFConditional::dispatch();
}

WFConditional *WFResourcePool::get(SubTask *task, void **resbuf)
{
	return new __WFConditional(task, resbuf, &this->data);
}

WFResourcePool::WFResourcePool(void *const *res, size_t n)
{
	this->data.res = new void *[n];
	memcpy(this->data.res, res, n * sizeof (void *));
	this->data.value = n;
	this->data.index = 0;
	INIT_LIST_HEAD(&this->data.wait_list);
	this->data.pool = this;
}

void WFResourcePool::post(void *res)
{
	struct WFResourcePool::Data *data = &this->data;
	WFConditional *cond;

	data->mutex.lock();
	if (++data->value <= 0)
	{
		cond = list_entry(data->wait_list.next, __WFConditional, list);
		list_del(data->wait_list.next);
	}
	else
	{
		cond = NULL;
		this->push(res);
	}

	data->mutex.unlock();
	if (cond)
		cond->WFConditional::signal(res);
}


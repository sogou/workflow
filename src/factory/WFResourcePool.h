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

#ifndef _WFRESOURCEPOOL_H_
#define _WFRESOURCEPOOL_H_

#include <mutex>
#include <atomic>
#include "list.h"
#include "WFTask.h"

class WFResourcePool
{
public:
	WFConditional *get(SubTask *task, void **pres);
	void post(void *res);

public:
	struct Data
	{
		void **res;
		std::atomic<int> value;
		std::atomic<int> index;
		struct list_head wait_list;
		std::mutex mutex;
		WFResourcePool *ptr;

		virtual void *pop()
		{
			return this->ptr->pop();
		}

		virtual void push(void *res)
		{
			this->ptr->push(res);
		}
	};

private:
	virtual void *pop()
	{
		return this->data.res[this->data.index++];
	}

	virtual void push(void *res)
	{
		this->data.res[--this->data.index] = res;
	}

private:
	struct Data data;

public:
	WFResourcePool(const void **res, int n)
	{
		this->data.ptr = this;
		this->data.res = new void *[n];
		memcpy(this->data.res, res, n * sizeof(void *));
		this->data.value = n;
		this->data.index = 0;
		INIT_LIST_HEAD(&this->data.wait_list);
	}

	virtual ~WFResourcePool() { delete[] this->data.res; }
};

#endif


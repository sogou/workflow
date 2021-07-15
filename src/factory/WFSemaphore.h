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

#ifndef _WFSEMAPHORE_H_
#define _WFSEMAPHORE_H_

#include <mutex>
#include <atomic>
#include "list.h"
#include "WFTask.h"
#include "WFCondition.h"

class WFSemaphore
{
public:
	WFConditional *get(SubTask *task, void **pmsg);
	void post(void *msg);

public:
	struct Data
	{
		void **sembuf;
		std::atomic<int> value;
		std::atomic<int> index;
		struct list_head wait_list;
		std::mutex mutex;
	};

private:
	struct Data data;

public:
	WFSemaphore(void **sembuf, int nsems)
	{
		this->data.sembuf = sembuf;
		this->data.value = nsems;
		this->data.index = 0;
		INIT_LIST_HEAD(&this->data.wait_list);
	}
};

#endif


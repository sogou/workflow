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

#ifndef _WFCONDITION_H_
#define _WFCONDITION_H_

#include <mutex>
#include <time.h>
#include <functional>
#include "list.h"
#include "WFTask.h"

class WFCondition
{
public:
	WFCondition()
	{
		INIT_LIST_HEAD(&this->waiter_list);
	}

	WFCounterTask *create_wait_task(std::function<void (WFCounterTask *)> cb);
	WFCounterTask *create_timedwait_task(const struct timespec *abstime,
										 std::function<void (WFCounterTask *)> cb);
	void signal();
	void broadcast();

public:
	std::mutex mutex;
private:
	struct list_head waiter_list;
};

#endif


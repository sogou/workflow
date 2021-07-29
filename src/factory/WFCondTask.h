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

#ifndef _WFCONDTASK_H_
#define _WFCONDTASK_H_

#include <mutex>
#include <atomic>
#include "list.h"
#include "WFTask.h"
#include "WFCondition.h"
#include "WFTaskFactory.h"
#include "WFCondTaskFactory.h"

class __WFWaitTimerTask;

class WFCondWaitTask : public WFMailboxTask
{
public:
	virtual void clear_locked() { }

protected:
	virtual SubTask *done();

private:
	struct list_head list;

private:
	void *msg;

public:
	WFCondWaitTask(wait_callback_t&& cb) :
		WFMailboxTask(&this->msg, 1, std::move(cb))
	{ }

	virtual ~WFCondWaitTask() { }

	friend class __WFWaitTimerTask;
	friend class WFCondition;
	friend class WFCondTaskFactory;
	friend class __ConditionMap;
};

#endif


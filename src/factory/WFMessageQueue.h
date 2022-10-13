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

#ifndef _WFMESSAGEQUEUE_H_
#define _WFMESSAGEQUEUE_H_

#include <mutex>
#include "list.h"
#include "WFTask.h"

class WFMessageQueue
{
public:
	WFConditional *get(SubTask *task, void **msgbuf);
	WFConditional *get(SubTask *task);
	void post(void *msg);

public:
	struct Data
	{
		void *pop() { return this->queue->pop(); }
		void push(void *msg) { this->queue->push(msg); }

		struct list_head msg_list;
		struct list_head wait_list;
		std::mutex mutex;
		WFMessageQueue *queue;
	};

protected:
	struct MessageEntry
	{
		struct list_head list;
		void *msg;
	};

protected:
	virtual void *pop()
	{
		struct MessageEntry *entry;
		void *msg;

		entry = list_entry(this->data.msg_list.next, struct MessageEntry, list);
		list_del(&entry->list);
		msg = entry->msg;
		delete entry;

		return msg;
	}

	virtual void push(void *msg)
	{
		struct MessageEntry *entry = new struct MessageEntry;
		entry->msg = msg;
		list_add_tail(&entry->list, &this->data.msg_list);
	}

protected:
	struct Data data;

public:
	WFMessageQueue()
	{
		INIT_LIST_HEAD(&this->data.msg_list);
		INIT_LIST_HEAD(&this->data.wait_list);
		this->data.queue = this;
	}

	virtual ~WFMessageQueue() { }
};

#endif


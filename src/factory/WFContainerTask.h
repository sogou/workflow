/*
  Copyright (c) 2020 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Xie Han (xiehan@sogou-inc.com)
*/

#ifndef _WFCONTAINERTASK_H_
#define _WFCONTAINERTASK_H_

#include <string.h>
#include <functional>
#include <atomic>
#include <type_traits>
#include "WFTask.h"

template<typename T>
class WFContainerTask : public WFCounterTask
{
public:
	void push(const T& value)
	{
		*this->cur++ = value;
		this->WFCounterTask::count();
	}

	void push(T&& value)
	{
		*this->cur++ = std::move(value);
		this->WFCounterTask::count();
	}

	T& operator[] (unsigned int n) { return this->value[n]; }

	void push_empty()
	{
		T *cur = this->cur++;

		if (std::is_pod<T>::value)
			memset(cur, 0, sizeof (T));

		this->WFCounterTask::count();
	}

public:
	void set_callback(std::function<void (WFContainerTask<T> *)> cb)
	{
		this->callback = std::move(cb);
	}

protected:
	virtual void count()
	{
		this->WFContainerTask::push_empty();
	}

protected:
	T *values;
	std::atomic<T *> cur;
	std::function<void (WFContainerTask<T> *)> callback;

private:
	static void wrapper(WFCounterTask *task)
	{
		WFContainerTask<T> *container = static_cast<WFContainerTask *>(task);
		container->callback(container);
	}

public:
	WFContainerTask(unsigned int size,
					std::function<void (WFContainerTask<T> *)>&& cb) :
		WFCounterTask(size, WFContainerTask<T>::wrapper),
		callback(std::move(cb))
	{
		this->values = new T[size];
		this->cur = this->values;
	}

protected:
	virtual ~WFContainerTask()
	{
		delete []this->values;
	}
};

#endif


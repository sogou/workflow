/*
  Copyright (c) 2019 Sogou, Inc.

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

#ifndef _WFCONNECTION_H_
#define _WFCONNECTION_H_

#include <utility>
#include <atomic>
#include <functional>
#include "Communicator.h"

class WFConnection : public CommConnection
{
public:
	void *get_context() const
	{
		return this->context;
	}

	void set_context(void *context, std::function<void (void *)> deleter)
	{
		this->context = context;
		this->deleter = std::move(deleter);
	}

	void set_context(void *context)
	{
		this->context = context;
	}

	void *test_set_context(void *test_context, void *new_context,
						   std::function<void (void *)> deleter)
	{
		if (this->context.compare_exchange_strong(test_context, new_context))
		{
			this->deleter = std::move(deleter);
			return new_context;
		}

		return test_context;
	}

	void *test_set_context(void *test_context, void *new_context)
	{
		if (this->context.compare_exchange_strong(test_context, new_context))
			return new_context;

		return test_context;
	}

private:
	std::atomic<void *> context;
	std::function<void (void *)> deleter;

public:
	WFConnection() : context(NULL) { }

protected:
	virtual ~WFConnection()
	{
		if (this->deleter)
			this->deleter(this->context);
	}
};

#endif


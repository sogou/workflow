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

#ifndef _IOREQUEST_H_
#define _IOREQUEST_H_

#include <errno.h>
#include "SubTask.h"
#include "Communicator.h"

class IORequest : public SubTask, public IOSession
{
public:
	IORequest(IOService *service)
	{
		this->service = service;
	}

public:
	virtual void dispatch()
	{
		if (this->service->request(this) < 0)
			this->handle(IOS_STATE_ERROR, errno);
	}

protected:
	int state;
	int error;

protected:
	IOService *service;

protected:
	virtual void handle(int state, int error)
	{
		this->state = state;
		this->error = error;
		this->subtask_done();
	}
};

#endif


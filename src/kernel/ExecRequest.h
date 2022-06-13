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

#ifndef _EXECREQUEST_H_
#define _EXECREQUEST_H_

#include "SubTask.h"
#include "Executor.h"

class ExecRequest : public SubTask, public ExecSession
{
public:
	ExecRequest(ExecQueue *queue, Executor *executor)
	{
		this->executor = executor;
		this->queue = queue;
	}

	ExecQueue *get_request_queue() const { return this->queue; }
	void set_request_queue(ExecQueue *queue) { this->queue = queue; }

public:
	virtual void dispatch()
	{
		if (this->executor->request(this, this->queue) < 0)
			this->handle(ES_STATE_ERROR, errno);
	}

protected:
	int state;
	int error;

protected:
	ExecQueue *queue;
	Executor *executor;

protected:
	virtual void handle(int state, int error)
	{
		this->state = state;
		this->error = error;
		this->subtask_done();
	}
};

#endif


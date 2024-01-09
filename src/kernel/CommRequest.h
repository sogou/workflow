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

#ifndef _COMMREQUEST_H_
#define _COMMREQUEST_H_

#include <errno.h>
#include <stddef.h>
#include "SubTask.h"
#include "Communicator.h"
#include "CommScheduler.h"

class CommRequest : public SubTask, public CommSession
{
public:
	CommRequest(CommSchedObject *object, CommScheduler *scheduler)
	{
		this->scheduler = scheduler;
		this->object = object;
		this->wait_timeout = 0;
	}

	CommSchedObject *get_request_object() const { return this->object; }
	void set_request_object(CommSchedObject *object) { this->object = object; }
	int get_wait_timeout() const { return this->wait_timeout; }
	void set_wait_timeout(int timeout) { this->wait_timeout = timeout; }

public:
	virtual void dispatch()
	{
		if (this->scheduler->request(this, this->object, this->wait_timeout,
									 &this->target) < 0)
		{
			this->handle(CS_STATE_ERROR, errno);
		}
	}

protected:
	int state;
	int error;

protected:
	CommTarget *target;
#define TOR_NOT_TIMEOUT			0
#define TOR_WAIT_TIMEOUT		1
#define TOR_CONNECT_TIMEOUT		2
#define TOR_TRANSMIT_TIMEOUT	3
	int timeout_reason;

protected:
	int wait_timeout;
	CommSchedObject *object;
	CommScheduler *scheduler;

protected:
	virtual void handle(int state, int error);
};

#endif


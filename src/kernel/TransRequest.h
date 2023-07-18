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

  Author: Xie Han (xiehan@sogou-inc.com)
*/

#ifndef _TRANSREQUEST_H_
#define _TRANSREQUEST_H_

#include "SubTask.h"
#include "Communicator.h"
#include "CommScheduler.h"

class ChanRequest : public SubTask, public CommChannel
{
public:
	ChanRequest(CommSchedObject *object, CommScheduler *scheduler)
	{
		this->scheduler = scheduler;
		this->object = object;
		this->wait_timeout = 0;
		this->established = 0;
	}

	CommSchedObject *get_request_object() const { return this->object; }
	void set_request_object(CommSchedObject *object) { this->object = object; }
	int get_wait_timeout() const { return this->wait_timeout; }
	void set_wait_timeout(int timeout) { this->wait_timeout = timeout; }

public:
	virtual void dispatch();

protected:
	int state;
	int error;

protected:
	CommTarget *target;

protected:
	int established;
	int wait_timeout;
	CommSchedObject *object;
	CommScheduler *scheduler;

protected:
	virtual void handle_established()
	{
		this->state = CS_STATE_SUCCESS;
		this->error = 0;
		this->established = 1;
		this->subtask_done();
	}

	virtual void handle(int state, int error)
	{
		this->state = state;
		this->error = error;
		this->established = 0;
		this->subtask_done();
	}
};

class TransRequest : public SubTask, public TransSession
{
public:
	TransRequest(CommChannel *channel, CommScheduler *scheduler)
	{
		this->scheduler = scheduler;
		this->channel = channel;
	}

	CommChannel *get_request_channel() const { return this->channel; }
	void set_request_channel(CommChannel *channel) { this->channel = channel; }

public:
	virtual void dispatch();

protected:
	int state;
	int error;

protected:
	CommChannel *channel;
	CommScheduler *scheduler;

protected:
	virtual void handle(int state, int error)
	{
		this->state = state;
		this->error = error;
		this->subtask_done();
	}
};

#endif


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

#ifndef _COMPLEXCHANNEL_H_
#define _COMPLEXCHANNEL_H_

#include "TransRequest.h"
#include "WFTaskFactory.h"
#include "WFChannel.h"
#include "WFGlobal.h"
#include "WFCondition.h"
#include "WFNameService.h"

template<class MSG>
class WFComplexChannel : public WFChannel<MSG>
{
public:
	WFComplexChannel(CommSchedObject *object, CommScheduler *scheduler,
					 std::function<void (WFChannelTask<MSG> *)>&& process) :
		WFChannel<MSG>(object, scheduler, std::move(process)),
		mutex(PTHREAD_MUTEX_INITIALIZER)
	{
		this->state = WFT_STATE_UNDEFINED;
		this->error = 0;
		this->sending = false;
	}

public:
	int get_error() const { return this->error; }

	void set_state(int state) { this->state = state; }
	int get_state() const { return this->state; }

	void set_sending(bool sending) { this->sending = sending; }
	bool get_sending() const { return this->sending; }

protected:
	virtual void dispatch();
	virtual SubTask *done();
	virtual WFRouterTask *route() = 0;

public:
	pthread_mutex_t mutex;
	WFCondition condition;

protected:
	bool sending;
	WFRouterTask *router_task;
};

template<class MSG>
class ComplexChannel : public WFComplexChannel<MSG>
{
public:
	ComplexChannel(CommSchedObject *object, CommScheduler *scheduler,
				   std::function<void (WFChannelTask<MSG> *)>&& process) :
		WFComplexChannel<MSG>(object, scheduler, std::move(process))
	{}

	void set_uri(const ParsedURI& uri) { this->uri = uri; }
	const ParsedURI *get_uri() const { return &this->uri; }

protected:
	virtual SubTask *done();
	virtual WFRouterTask *route();
	virtual void router_callback(WFRouterTask *task);

protected:
	ParsedURI uri;
	WFNSPolicy *ns_policy;
	RouteManager::RouteResult route_result;
};

template<class MSG>
class ComplexChannelOutTask : public WFChannelOutTask<MSG>
{
public:
	ComplexChannelOutTask(CommChannel *channel, CommScheduler *scheduler,
						  std::function<void (WFChannelTask<MSG> *)>&& cb) :
		WFChannelOutTask<MSG>(channel, scheduler, std::move(cb))
	{
		this->ready = true;
	}

	virtual ~ComplexChannelOutTask()
	{}

protected:
	virtual void dispatch();
	virtual SubTask *upgrade();
	virtual SubTask *done();
	void upgrade_callback(WFCounterTask *task);

	void counter_callback(WFCounterTask *task)
	{
		auto *channel = static_cast<ComplexChannel<MSG> *>(this->get_request_channel());
		channel->set_state(WFT_STATE_SUCCESS);
		this->ready = true;
	}

protected:
	bool ready;
};

#include "ComplexChannel.inl"

#endif


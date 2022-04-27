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

#ifndef _WFNAMESERVICE_H_
#define _WFNAMESERVICE_H_

#include <pthread.h>
#include <functional>
#include <utility>
#include "rbtree.h"
#include "Communicator.h"
#include "Workflow.h"
#include "WFTask.h"
#include "RouteManager.h"
#include "URIParser.h"
#include "EndpointParams.h"

class WFRouterTask : public WFGenericTask
{
public:
	RouteManager::RouteResult *get_result() { return &this->result; }

public:
	void set_state(int state) { this->state = state; }
	void set_error(int error) { this->error = error; }

protected:
	RouteManager::RouteResult result;
	std::function<void (WFRouterTask *)> callback;

protected:
	virtual SubTask *done()
	{
		SeriesWork *series = series_of(this);

		if (this->callback)
			this->callback(this);

		delete this;
		return series->pop();
	}

public:
	WFRouterTask(std::function<void (WFRouterTask *)>&& cb) :
		callback(std::move(cb))
	{
	}
};

class WFNSTracing
{
public:
	void *data;
	void (*deleter)(void *);

public:
	WFNSTracing()
	{
		this->data = NULL;
		this->deleter = NULL;
	}
};

struct WFNSParams
{
	TransportType type;
	ParsedURI& uri;
	const char *info;
	bool fixed_addr;
	int retry_times;
	WFNSTracing *tracing;
};

using router_callback_t = std::function<void (WFRouterTask *)>;

class WFNSPolicy
{
public:
	virtual WFRouterTask *create_router_task(const struct WFNSParams *params,
											 router_callback_t callback) = 0;

	virtual void success(RouteManager::RouteResult *result,
						 WFNSTracing *tracing,
						 CommTarget *target)
	{
		RouteManager::notify_available(result->cookie, target);
	}

	virtual void failed(RouteManager::RouteResult *result,
						WFNSTracing *tracing,
						CommTarget *target)
	{
		if (target)
			RouteManager::notify_unavailable(result->cookie, target);
	}

public:
	virtual ~WFNSPolicy() { }
};

class WFNameService
{
public:
	int add_policy(const char *name, WFNSPolicy *policy);
	WFNSPolicy *get_policy(const char *name);
	WFNSPolicy *del_policy(const char *name);

public:
	WFNSPolicy *get_default_policy() const
	{
		return this->default_policy;
	}

	void set_default_policy(WFNSPolicy *policy)
	{
		this->default_policy = policy;
	}

private:
	WFNSPolicy *default_policy;
	struct rb_root root;
	pthread_rwlock_t rwlock;

private:
	struct WFNSPolicyEntry *get_policy_entry(const char *name);

public:
	WFNameService(WFNSPolicy *default_policy) :
		rwlock(PTHREAD_RWLOCK_INITIALIZER)
	{
		this->root.rb_node = NULL;
		this->default_policy = default_policy;
	}

	virtual ~WFNameService();
};

#endif


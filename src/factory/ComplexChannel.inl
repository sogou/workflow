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

#include "WFTask.h"
#include "WFChannel.h"
#include "RouteManager.h"
#include "EndpointParams.h"

template<class MSG>
void WFComplexChannel<MSG>::dispatch()
{
	if (this->object)
		return this->WFChannel<MSG>::dispatch();

	if (this->state == WFT_STATE_UNDEFINED)
	{
		this->router_task = this->route();
		series_of(this)->push_front(this);
		series_of(this)->push_front(this->router_task);
	}

	this->subtask_done();
}

template<class MSG>
SubTask *WFComplexChannel<MSG>::done()
{
	SeriesWork *series = series_of(this);

	if (this->router_task)
	{
		this->router_task = NULL;
		return series->pop();
	}

	if (this->callback)
		this->callback(this);

	if (this->state == WFT_STATE_SUCCESS)
		this->state = WFT_STATE_UNDEFINED;

	if (this->established == 0 && this->state == WFT_STATE_SUCCESS)
		delete this;

	return series->pop();
}

template<class MSG>
SubTask *ComplexChannel<MSG>::done()
{
	if (this->established == 1)
	{
		if (this->state == WFT_STATE_SYS_ERROR)
			this->ns_policy->failed(&this->route_result, NULL, this->target);
		else
			this->ns_policy->success(&this->route_result, NULL, this->target);
	}

	return WFComplexChannel<MSG>::done();
}

template<class MSG>
WFRouterTask *ComplexChannel<MSG>::route()
{
	auto&& cb = std::bind(&ComplexChannel<MSG>::router_callback,
						  this, std::placeholders::_1);
	struct WFNSParams params = {
		.type			=	TT_TCP,
		.uri			=	this->uri,
		.info			=	"",
		.fixed_addr		=	true,
		.retry_times	=	0,
		.tracing		=	NULL,
	};

	WFNameService *ns = WFGlobal::get_name_service();
	this->ns_policy = ns->get_policy(this->uri.host ? this->uri.host : "");
	return this->ns_policy->create_router_task(&params, cb);
}

template<class MSG>
void ComplexChannel<MSG>::router_callback(WFRouterTask *task)
{
	if (task->get_state() == WFT_STATE_SUCCESS)
	{
		this->route_result = std::move(*task->get_result());
		this->set_request_object(this->route_result.request_object);
	}
	else
	{
		this->state = task->get_state();
		this->error = task->get_error();
	}
}

template<class MSG>
void ComplexChannelOutTask<MSG>::dispatch()
{
	int ret = false;
	auto *channel = static_cast<ComplexChannel<MSG> *>(this->get_request_channel());

	if (this->state == WFT_STATE_SYS_ERROR)
		return this->subtask_done();

	pthread_mutex_lock(&channel->mutex);

	switch (channel->get_state())
	{
	case WFT_STATE_UNDEFINED:
		if (channel->get_sending() == false)
		{
			series_of(this)->push_front(this);
			series_of(this)->push_front(channel);
			channel->set_sending(true);
			this->ready = false;
		}
		else if (this->ready == false)
		{
			SubTask *upgrade_task = this->upgrade();
			series_of(this)->push_front(this);
			series_of(this)->push_front(upgrade_task);
			//this->upgrade_state = CHANNEL_TASK_WAITING;
		}
		else
		{
			auto&& cb = std::bind(&ComplexChannelOutTask<MSG>::counter_callback,
								  this, std::placeholders::_1);
			WFCounterTask *counter = channel->condition.create_wait_task(cb);
			series_of(this)->push_front(this);
			series_of(this)->push_front(counter);
			this->ready = false;
		}
		break;

	case WFT_STATE_SUCCESS:
		if (channel->get_sending() == false)
		{
			channel->set_sending(true);
			ret = true;
		}
		else
		{
			auto&& cb = std::bind(&ComplexChannelOutTask<MSG>::counter_callback,
								  this, std::placeholders::_1);
			WFCounterTask *counter = channel->condition.create_wait_task(cb);
			series_of(this)->push_front(this);
			series_of(this)->push_front(counter);
			this->ready = false;
		}
		break;

	default:
		break;
	}

	pthread_mutex_unlock(&channel->mutex);

	if (ret == true)
		return this->WFChannelOutTask<MSG>::dispatch();

	return this->subtask_done();
}

template<class MSG>
SubTask *ComplexChannelOutTask<MSG>::upgrade()
{
	auto&& cb = std::bind(&ComplexChannelOutTask<MSG>::upgrade_callback,
						  this, std::placeholders::_1);
	return new WFCounterTask(0, cb);
}

template<class MSG>
SubTask *ComplexChannelOutTask<MSG>::done()
{
	auto *channel = static_cast<ComplexChannel<MSG> *>(this->get_request_channel());

	if (channel->get_state() == WFT_STATE_UNDEFINED ||
		channel->get_state() == WFT_STATE_SUCCESS)
	{
		if (this->ready != true)
			return series_of(this)->pop();
	}
	else
	{
		this->state = channel->get_state();
		this->error = channel->get_error();
	}

	pthread_mutex_lock(&channel->mutex);
	channel->set_sending(false);
	channel->condition.signal();
	pthread_mutex_unlock(&channel->mutex);

	return WFChannelOutTask<MSG>::done();
}

template<class MSG>
void ComplexChannelOutTask<MSG>::upgrade_callback(WFCounterTask *task)
{
	auto *channel = static_cast<ComplexChannel<MSG> *>(this->get_request_channel());

	pthread_mutex_lock(&channel->mutex);
	channel->set_state(WFT_STATE_SUCCESS);
	this->ready = true;
	channel->set_sending(false);
	channel->condition.signal();
	pthread_mutex_unlock(&channel->mutex);
}


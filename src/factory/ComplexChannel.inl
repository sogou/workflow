#include "WFTask.h"
#include "WFChannel.h"
#include "ComplexChannel.h"

template<class MESSAGE>
void WFComplexChannel<MESSAGE>::dispatch()
{
	if (this->object)
		return this->WFChannel<MESSAGE>::dispatch();

	if (this->state == WFT_STATE_UNDEFINED)
	{
		this->router_task = this->route();
		series_of(this)->push_front(this);
		series_of(this)->push_front(this->router_task);
	}

	this->subtask_done();
}

template<class MESSAGE>
SubTask *WFComplexChannel<MESSAGE>::done()
{
	SeriesWork *series = series_of(this);

	if (this->router_task)
	{
		this->router_task = NULL;
		return series->pop();
	}

	if (this->callback)
		this->callback(this);

	return series->pop();
}

template<class MESSAGE>
SubTask *ComplexChannel<MESSAGE>::done()
{
	if (this->established == 1)
	{
		if (this->state == WFT_STATE_SYS_ERROR)
			this->ns_policy->failed(&this->route_result, NULL, this->target);
		else
			this->ns_policy->success(&this->route_result, NULL, this->target);
	}

	return WFComplexChannel<MESSAGE>::done();
}

template<class MESSAGE>
WFRouterTask *ComplexChannel<MESSAGE>::route()
{
	auto&& cb = std::bind(&ComplexChannel<MESSAGE>::router_callback,
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

template<class MESSAGE>
void ComplexChannel<MESSAGE>::router_callback(WFRouterTask *task)
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

template<class MESSAGE>
void ComplexChannelOutTask<MESSAGE>::dispatch()
{
	int ret = false;
	auto *channel = static_cast<ComplexChannel<MESSAGE> *>(this->get_request_channel());

	pthread_mutex_lock(&channel->mutex);

	switch (channel->get_state())
	{
	case WFT_STATE_UNDEFINED:
		if (!channel->is_established())
		{
			series_of(this)->push_front(this);
			series_of(this)->push_front(channel);
		}
		else if (!this->upgrading)
		{
			SubTask *upgrade_task = this->upgrade();
			series_of(this)->push_front(this);
			series_of(this)->push_front(upgrade_task);
		}
		else
		{
			auto&& cb = std::bind(&ComplexChannelOutTask<MESSAGE>::counter_callback,
								  this, std::placeholders::_1);
			WFCounterTask *counter = new WFCounterTask(1, cb); //
			series_of(this)->push_front(this);
			series_of(this)->push_front(counter);
			channel->set_counter(counter);
		}
		break;
	case WFT_STATE_SUCCESS:
		ret = true;
	default:
		break;
	}

	pthread_mutex_unlock(&channel->mutex);

	if (ret == true)
		return this->ChannelOutTask<MESSAGE>::dispatch();

	return this->subtask_done();
}

template<class MESSAGE>
SubTask *ComplexChannelOutTask<MESSAGE>::upgrade()
{
	this->upgrading = true;
	auto&& cb = std::bind(&ComplexChannelOutTask<MESSAGE>::upgrade_callback,
						  this, std::placeholders::_1);
	return new WFCounterTask(0, cb);
}

template<class MESSAGE>
SubTask *ComplexChannelOutTask<MESSAGE>::done()
{
	SeriesWork *series = series_of(this);
	auto *channel = static_cast<ComplexChannel<MESSAGE> *>(this->get_request_channel());

	if (channel->get_state() == WFT_STATE_UNDEFINED ||
		 channel->get_state() == WFT_STATE_SUCCESS)
	{
		if (!channel->is_established() || this->upgrading)
			return series->pop();
	}
	else
	{
		this->state = channel->get_state();
		this->error = channel->get_error();
	}

	return ChannelOutTask<MESSAGE>::done();
}

template<class MESSAGE>
void ComplexChannelOutTask<MESSAGE>::upgrade_callback(WFCounterTask *task)
{
	auto *channel = static_cast<ComplexChannel<MESSAGE> *>(this->get_request_channel());
	channel->set_state(WFT_STATE_SUCCESS);
	this->upgrading = false;
}


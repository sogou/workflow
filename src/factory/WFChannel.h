#ifndef _WFCHANNEL_H_
#define _WFCHANNEL_H_

#include "CommScheduler.h"
#include "TransRequest.h"
#include "Workflow.h"
//#include "RouteManager.h"
//#include "EndpointParams.h"
//#include "WFNameService.h"

template<class MSG>
class WFChannelTask : public TransRequest
{
public:
	void start()
	{
		assert(!series_of(this));
		Workflow::start_series_work(this, nullptr);
	}

	void dismiss()
	{
		assert(!series_of(this));
		delete this;
	}

public:
	MSG *get_msg()
	{
		return &this->msg;
	}

public:
	void *user_data;

public:
	int get_state() const { return this->state; }
	int get_error() const { return this->error; }

	void set_callback(std::function<void (WFChannelTask<MSG> *)> cb)
	{
		this->callback = std::move(cb);
	}

protected:
	virtual SubTask *done()
	{
		SeriesWork *series = series_of(this);

		if (this->callback)
			this->callback(this);

		delete this;
		return series->pop();
	}

protected:
	MSG msg;
	std::function<void (WFChannelTask<MSG> *)> callback;

public:
	WFChannelTask(CommChannel *channel, CommScheduler *scheduler,
				std::function<void (WFChannelTask<MSG> *)>&& cb) :
		TransRequest(channel, scheduler),
		callback(std::move(cb))
	{
	}

	virtual ~WFChannelTask() { }
};

#include "WFChannel.inl"

#endif


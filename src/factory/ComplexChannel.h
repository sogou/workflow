#ifndef _COMPLEXCHANNEL_H_
#define _COMPLEXCHANNEL_H_

#include "TransRequest.h"
#include "WFTaskFactory.h"
#include "WFChannel.h"
#include "WFGlobal.h"
#include "WFCondition.h"

template<class MESSAGE>
class WFComplexChannel : public WFChannel<MESSAGE>
{
public://private: and friend to Factory
	WFComplexChannel(CommSchedObject *object, CommScheduler *scheduler,
					 std::function<void (ChannelTask<MESSAGE> *)>&& process) :
		WFChannel<MESSAGE>(object, scheduler, std::move(process)),
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

template<class MESSAGE>
class ComplexChannel : public WFComplexChannel<MESSAGE>
{
public:
	ComplexChannel(CommSchedObject *object, CommScheduler *scheduler,
				   std::function<void (ChannelTask<MESSAGE> *)>&& process) :
		WFComplexChannel<MESSAGE>(object, scheduler, std::move(process))
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

template<class MESSAGE>
class ComplexChannelOutTask : public ChannelOutTask<MESSAGE>
{
public:
	ComplexChannelOutTask(CommChannel *channel, CommScheduler *scheduler,
						  std::function<void (ChannelTask<MESSAGE> *)>&& cb) :
		ChannelOutTask<MESSAGE>(channel, scheduler, std::move(cb))
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
		auto *channel = static_cast<ComplexChannel<MESSAGE> *>(this->get_request_channel());
		channel->set_state(WFT_STATE_SUCCESS);
		this->ready = true;
	}

protected:
	bool ready;
};

#include "ComplexChannel.inl"

#endif


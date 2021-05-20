#ifndef _COMPLEXCHANNEL_H_
#define _COMPLEXCHANNEL_H_

#include "TransRequest.h"
#include "WFChannel.h"
#include "WFTaskFactory.h"
#include "WFGlobal.h"

template<class MESSAGE>
class WFComplexChannel : public WFChannel<MESSAGE>
{
public:
	WFComplexChannel(CommSchedObject *object, CommScheduler *scheduler,
					 std::function<void (ChannelTask<MESSAGE> *)>&& process) :
		WFChannel<MESSAGE>(object, scheduler, std::move(process)),
		mutex(PTHREAD_MUTEX_INITIALIZER)
	{
		this->state = WFT_STATE_UNDEFINED;
		this->error = 0;
		this->name = "";//TODO
		this->sending = false;
	}

	int get_error() const { return this->error; }

	void set_state(int state) { this->state = state; }
	int get_state() const { return this->state; }

	void set_sending(bool sending) { this->sending = sending; }
	bool get_sending() const { return this->sending; }

	void count() { WFTaskFactory::count_by_name(this->name, 1); }
	std::string get_name() { return this->name; }
protected:
	virtual void dispatch();
	virtual SubTask *done();
	virtual WFRouterTask *route() = 0;

public:
	pthread_mutex_t mutex;

protected:
//	WFCounterTask *counter;
	std::string name;
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
		this->upgrade_state = CHANNEL_TASK_INIT;
	}

protected:
	virtual void dispatch();
	virtual SubTask *upgrade();
	virtual SubTask *done();
	void upgrade_callback(WFCounterTask *task);

	void counter_callback(WFCounterTask *task)
	{
		auto *channel = static_cast<ComplexChannel<MESSAGE> *>(this->get_request_channel());
		channel->set_state(WFT_STATE_SUCCESS);
		this->upgrade_state = CHANNEL_TASK_INIT;
	}

protected:
	int upgrade_state; // 0: not init; 1: upgrading; 2: counter;
	enum
	{
		CHANNEL_TASK_INIT = 0,
		CHANNEL_TASK_UPGRADING,
		CHANNEL_TASK_WAITING,
	};
};

#include "ComplexChannel.inl"

#endif


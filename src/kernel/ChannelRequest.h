#ifndef _CHANNEL_REQUEST_H_
#define _CHANNEL_REQUEST_H_

#include "Communicator.h"
#include "SubTask.h"

#define CHANNEL_STATE_UNDEFINED		-1
#define CHANNEL_STATE_ESTABLISHED	0
#define CHANNEL_STATE_ERROR			CS_STATE_ERROR
#define CHANNEL_STATE_STOPPED		CS_STATE_STOPPED
#define CHANNEL_STATE_SHUTDOWN		CS_STATE_SHUTDOWN

#define CHANNEL_SUCCESS				0
#define CHANNEL_ERROR_UNOPEN		CHANNEL_STATE_UNDEFINED
#define CHANNEL_ERROR_STOPPED		CHANNEL_STATE_STOPPED
#define CHANNEL_ERROR_SENDING		3
#define CHANNEL_ERROR_SEND			4

class ChannelRequest;

class CommSchedChannel : public CommChannel
{
public:
	CommSchedChannel(Communicator *comm, CommTarget *target) :
		send_mutex(PTHREAD_MUTEX_INITIALIZER)
	{
		this->communicator = comm;
		this->target = target;
		this->state = CHANNEL_STATE_UNDEFINED;
	}

	bool establish()
	{
		if (this->state != CHANNEL_STATE_UNDEFINED &&
			this->state != CHANNEL_STATE_SHUTDOWN &&
			this->state != CHANNEL_STATE_STOPPED)
		{
			//errno = EINAVAIL;
			return false;
		}
		
		return !!this->communicator->establish(this, target);
	}

	virtual void handle_established()
	{
		this->state = CHANNEL_STATE_ESTABLISHED;
	}

	bool shutdown()
	{
		if (this->state != CHANNEL_STATE_ESTABLISHED)
			return false;

		this->communicator->shutdown(this);
		return true;
	}

	virtual void handle_terminated()
	{
		this->state = CHANNEL_STATE_SHUTDOWN;
	}

	int get_state() { return this->state; }

	// TODO: wait for handle finish and we can reuse this channel
	virtual void handle(int state, int error);
	virtual void handle_in(CommMessageIn *in);

protected:
	Communicator *communicator;
	CommTarget *target;
	pthread_mutex_t send_mutex;
	ChannelRequest *in_session;
	int state;
};

class ChannelRequest : public SubTask, public TransSession
{
public:
	ChannelRequest(CommChannel *channel, CommScheduler *scheduler)
	{
		this->sched_channel = channel;
		this->scheduler = scheduler;
		this->passive = false;
		this->wait_timeout = 0;
	}

	int get_wait_timeout() const { return this->wait_timeout; }
	void set_wait_timeout(int timeout) { this->wait_timeout = timeout; }
	CommChannel *get_sched_channel() const { return this->sched_channel; }

	virtual void dispatch();
	virtual void handle(int state, int error);

protected:
    int state;
    int error;
	bool passive;
	int wait_timeout;
	CommScheduler *scheduler;
	CommSchedChannel *sched_channel;
	friend CommChannel;
};

#endif


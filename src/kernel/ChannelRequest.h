#ifndef _CHANNEL_REQUEST_H_
#define _CHANNEL_REQUEST_H_

#include "Communicator.h"
#include "SubTask.h"

#define CHANNEL_SUCCESS				0
#define CHANNEL_ERROR_UNOPEN		-1
#define CHANNEL_ERROR_STOPPED		2
#define CHANNEL_ERROR_SENDING		3
#define CHANNEL_ERROR_SEND			4
/*
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

	virtual void handle(int state, int error);
*/

/*
class ShutdownSession : public SubTask, public TransSession
{
public:
	ShutdownSession(CommChannel *channel, CommScheduler *scheduler)
	{
		this->channel = channel;
		this->scheduler = scheduler;
	}

	virtual void dispatch()
	{
		this->scheduler->shutdown(this->channel);
	}

private:
	CommChannel *channel;
	CommScheduler *scheduler;
};
*/

class EstablishSession : public SubTask, public CommChannel
{
public:
	EstablishSession(CommChannel *channel, CommScheduler *scheduler,
					 CommSchedObject *object, int wait_timeout, CommTarget **target)
	{
		this->channel = channel;
		this->scheduler = scheduler;
		this->object = object;
		this->wait_timeout = wait_timeout;
		this->target = target;
	}

	virtual void dispatch()
	{
		if (this->scheduler->establish(this->channel, this->object,
									   this->wait_timeout, this->target) < 0)
		{
			this->handle(CS_STATE_ERROR, CHANNEL_ERROR_UNOPEN);
		}
	}

	virtual void handle(int state, int error)
	{
		this->state = state;
		this->error = error;
		this->subtask_done();
	}

private:
    int state;
    int error;
	int wait_timeout;
	CommTarget **target;
	CommChannel *channel;
	CommScheduler *scheduler;
	CommSchedObject *object;
};

class ChannelRequest : public SubTask, public TransSession
{
public:
	ChannelRequest(CommChannel *channel, CommScheduler *scheduler)
	{
		this->sched_channel = channel;
		this->scheduler = scheduler;
		this->passive = false;
	}

	CommChannel *get_sched_channel() const { return this->sched_channel; }

	virtual void dispatch()
	{
		fprintf(stderr, "ChannelRequest::dispatch()\n");
		if (!this->passive)
		{
			int ret = this->scheduler->send(this, this->sched_channel);

			if (ret < 0)
				this->handle(CHANNEL_STATE_ERROR, CHANNEL_ERROR_SEND);
			else if (ret == 1)
				this->handle(CS_STATE_SUCCESS, CHANNEL_SUCCESS);
		}
		else
		{
			this->process_message();
			this->subtask_done();
		}
	}

	virtual void handle(int state, int error)
	{
		this->state = state;
		this->error = error;
		this->subtask_done();
	}

	virtual void process_message() {}

protected:
    int state;
    int error;
	bool passive;
	CommScheduler *scheduler;
	CommChannel *sched_channel;
	friend CommChannel;
};

#endif


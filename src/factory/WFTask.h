/*
  Copyright (c) 2019 Sogou, Inc.

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

#ifndef _WFTASK_H_
#define _WFTASK_H_

#include <errno.h>
#include <string.h>
#include <assert.h>
#include <atomic>
#include <utility>
#include <functional>
#include "Executor.h"
#include "ExecRequest.h"
#include "Communicator.h"
#include "CommScheduler.h"
#include "CommRequest.h"
#include "SleepRequest.h"
#include "IORequest.h"
#include "Workflow.h"
#include "WFConnection.h"

enum
{
	WFT_STATE_UNDEFINED = -1,
	WFT_STATE_SUCCESS = CS_STATE_SUCCESS,
	WFT_STATE_TOREPLY = CS_STATE_TOREPLY,		/* for server task only */
	WFT_STATE_NOREPLY = CS_STATE_TOREPLY + 1,	/* for server task only */
	WFT_STATE_SYS_ERROR = CS_STATE_ERROR,
	WFT_STATE_SSL_ERROR = 65,
	WFT_STATE_DNS_ERROR = 66,					/* for client task only */
	WFT_STATE_TASK_ERROR = 67,
	WFT_STATE_ABORTED = CS_STATE_STOPPED
};

template<class INPUT, class OUTPUT>
class WFThreadTask : public ExecRequest
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
	INPUT *get_input() { return &this->input; }
	OUTPUT *get_output() { return &this->output; }

public:
	void *user_data;

public:
	int get_state() const { return this->state; }
	int get_error() const { return this->error; }

public:
	void set_callback(std::function<void (WFThreadTask<INPUT, OUTPUT> *)> cb)
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
	INPUT input;
	OUTPUT output;
	std::function<void (WFThreadTask<INPUT, OUTPUT> *)> callback;

public:
	WFThreadTask(ExecQueue *queue, Executor *executor,
				 std::function<void (WFThreadTask<INPUT, OUTPUT> *)>&& cb) :
		ExecRequest(queue, executor),
		callback(std::move(cb))
	{
		this->user_data = NULL;
		this->state = WFT_STATE_UNDEFINED;
		this->error = 0;
	}

protected:
	virtual ~WFThreadTask() { }
};

template<class REQ, class RESP>
class WFNetworkTask : public CommRequest
{
public:
	/* start(), dismiss() are for client tasks only. */
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
	REQ *get_req() { return &this->req; }
	RESP *get_resp() { return &this->resp; }

public:
	void *user_data;

public:
	int get_state() const { return this->state; }
	int get_error() const { return this->error; }

	/* Call when error is ETIMEDOUT, return values:
	 * TOR_NOT_TIMEOUT, TOR_WAIT_TIMEOUT, TOR_CONNECT_TIMEOUT,
	 * TOR_TRANSMIT_TIMEOUT (send or receive).
	 * SSL connect timeout also returns TOR_CONNECT_TIMEOUT. */
	int get_timeout_reason() const { return this->timeout_reason; }

	/* Call only in callback or server's process. */
	long long get_task_seq() const
	{
		if (!this->target)
		{
			errno = ENOTCONN;
			return -1;
		}

		return this->get_seq();
	}

	int get_peer_addr(struct sockaddr *addr, socklen_t *addrlen) const;

	virtual WFConnection *get_connection() const = 0;

public:
	/* All in milliseconds. timeout == -1 for unlimited. */
	void set_send_timeout(int timeout) { this->send_timeo = timeout; }
	void set_receive_timeout(int timeout) { this->receive_timeo = timeout; }
	void set_keep_alive(int timeout) { this->keep_alive_timeo = timeout; }

public:
	/* Do not reply this request. */
	void noreply()
	{
		if (this->state == WFT_STATE_TOREPLY)
			this->state = WFT_STATE_NOREPLY;
	}

	/* Push reply data synchronously. */
	virtual int push(const void *buf, size_t size)
	{
		return this->scheduler->push(buf, size, this);
	}

	/* To check if the connection was closed before replying.
	   Always returns 'true' in callback. */
	bool closed() const
	{
		switch (this->state)
		{
		case WFT_STATE_UNDEFINED:
			return false;
		case WFT_STATE_TOREPLY:
		case WFT_STATE_NOREPLY:
			return !this->target->has_idle_conn();
		default:
			return true;
		}
	}

public:
	void set_callback(std::function<void (WFNetworkTask<REQ, RESP> *)> cb)
	{
		this->callback = std::move(cb);
	}

protected:
	virtual int send_timeout() { return this->send_timeo; }
	virtual int receive_timeout() { return this->receive_timeo; }
	virtual int keep_alive_timeout() { return this->keep_alive_timeo; }

protected:
	int send_timeo;
	int receive_timeo;
	int keep_alive_timeo;
	REQ req;
	RESP resp;
	std::function<void (WFNetworkTask<REQ, RESP> *)> callback;

protected:
	WFNetworkTask(CommSchedObject *object, CommScheduler *scheduler,
				  std::function<void (WFNetworkTask<REQ, RESP> *)>&& cb) :
		CommRequest(object, scheduler),
		callback(std::move(cb))
	{
		this->send_timeo = -1;
		this->receive_timeo = -1;
		this->keep_alive_timeo = 0;
		this->target = NULL;
		this->timeout_reason = TOR_NOT_TIMEOUT;
		this->user_data = NULL;
		this->state = WFT_STATE_UNDEFINED;
		this->error = 0;
	}

	virtual ~WFNetworkTask() { }
};

class WFTimerTask : public SleepRequest
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
	void *user_data;

public:
	int get_state() const { return this->state; }
	int get_error() const { return this->error; }

public:
	void set_callback(std::function<void (WFTimerTask *)> cb)
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
	std::function<void (WFTimerTask *)> callback;

public:
	WFTimerTask(CommScheduler *scheduler,
				std::function<void (WFTimerTask *)> cb) :
		SleepRequest(scheduler),
		callback(std::move(cb))
	{
		this->user_data = NULL;
		this->state = WFT_STATE_UNDEFINED;
		this->error = 0;
	}

protected:
	virtual ~WFTimerTask() { }
};

template<class ARGS>
class WFFileTask : public IORequest
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
	ARGS *get_args() { return &this->args; }

	long get_retval() const
	{
		if (this->state == WFT_STATE_SUCCESS)
			return this->get_res();
		else
			return -1;
	}

public:
	void *user_data;

public:
	int get_state() const { return this->state; }
	int get_error() const { return this->error; }

public:
	void set_callback(std::function<void (WFFileTask<ARGS> *)> cb)
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
	ARGS args;
	std::function<void (WFFileTask<ARGS> *)> callback;

public:
	WFFileTask(IOService *service,
			   std::function<void (WFFileTask<ARGS> *)>&& cb) :
		IORequest(service),
		callback(std::move(cb))
	{
		this->user_data = NULL;
		this->state = WFT_STATE_UNDEFINED;
		this->error = 0;
	}

protected:
	virtual ~WFFileTask() { }
};

class WFGenericTask : public SubTask
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
	void *user_data;

public:
	int get_state() const { return this->state; }
	int get_error() const { return this->error; }

protected:
	virtual void dispatch()
	{
		this->subtask_done();
	}

	virtual SubTask *done()
	{
		SeriesWork *series = series_of(this);
		delete this;
		return series->pop();
	}

protected:
	int state;
	int error;

public:
	WFGenericTask()
	{
		this->user_data = NULL;
		this->state = WFT_STATE_UNDEFINED;
		this->error = 0;
	}

protected:
	virtual ~WFGenericTask() { }
};

class WFCounterTask : public WFGenericTask
{
public:
	virtual void count()
	{
		if (--this->value == 0)
		{
			this->state = WFT_STATE_SUCCESS;
			this->subtask_done();
		}
	}

public:
	void set_callback(std::function<void (WFCounterTask *)> cb)
	{
		this->callback = std::move(cb);
	}

protected:
	virtual void dispatch()
	{
		this->WFCounterTask::count();
	}

	virtual SubTask *done()
	{
		SeriesWork *series = series_of(this);

		if (this->callback)
			this->callback(this);

		delete this;
		return series->pop();
	}

protected:
	std::atomic<unsigned int> value;
	std::function<void (WFCounterTask *)> callback;

public:
	WFCounterTask(unsigned int target_value,
				  std::function<void (WFCounterTask *)>&& cb) :
		value(target_value + 1),
		callback(std::move(cb))
	{
	}

protected:
	virtual ~WFCounterTask() { }
};

class WFMailboxTask : public WFGenericTask
{
public:
	void send(void *msg)
	{
		*this->mailbox = msg;
		if (this->flag.exchange(true))
		{
			this->state = WFT_STATE_SUCCESS;
			this->subtask_done();
		}
	}

	void **get_mailbox() const
	{
		return this->mailbox;
	}

public:
	void set_callback(std::function<void (WFMailboxTask *)> cb)
	{
		this->callback = std::move(cb);
	}

protected:
	virtual void dispatch()
	{
		if (this->flag.exchange(true))
		{
			this->state = WFT_STATE_SUCCESS;
			this->subtask_done();
		}
	}

	virtual SubTask *done()
	{
		SeriesWork *series = series_of(this);

		if (this->callback)
			this->callback(this);

		delete this;
		return series->pop();
	}

protected:
	void **mailbox;
	std::atomic<bool> flag;
	std::function<void (WFMailboxTask *)> callback;

public:
	WFMailboxTask(void **mailbox,
				  std::function<void (WFMailboxTask *)>&& cb) :
		flag(false),
		callback(std::move(cb))
	{
		this->mailbox = mailbox;
	}

	WFMailboxTask(std::function<void (WFMailboxTask *)>&& cb) :
		flag(false),
		callback(std::move(cb))
	{
		this->mailbox = &this->user_data;
	}

protected:
	virtual ~WFMailboxTask() { }
};

class WFConditional : public WFGenericTask
{
public:
	virtual void signal(void *msg)
	{
		*this->msgbuf = msg;
		if (this->flag.exchange(true))
			this->subtask_done();
	}

protected:
	virtual void dispatch()
	{
		series_of(this)->push_front(this->task);
		this->task = NULL;
		if (this->flag.exchange(true))
			this->subtask_done();
	}

protected:
	std::atomic<bool> flag;
	SubTask *task;
	void **msgbuf;

public:
	WFConditional(SubTask *task, void **msgbuf) :
		flag(false)
	{
		this->task = task;
		this->msgbuf = msgbuf;
	}

	WFConditional(SubTask *task) :
		flag(false)
	{
		this->task = task;
		this->msgbuf = &this->user_data;
	}

protected:
	virtual ~WFConditional()
	{
		delete this->task;
	}
};

class WFGoTask : public ExecRequest
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
	void *user_data;

public:
	int get_state() const { return this->state; }
	int get_error() const { return this->error; }

public:
	void set_callback(std::function<void (WFGoTask *)> cb)
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
	std::function<void (WFGoTask *)> callback;

public:
	WFGoTask(ExecQueue *queue, Executor *executor) :
		ExecRequest(queue, executor)
	{
		this->user_data = NULL;
		this->state = WFT_STATE_UNDEFINED;
		this->error = 0;
	}

protected:
	virtual ~WFGoTask() { }
};

class WFRepeaterTask : public WFGenericTask
{
public:
	void set_create(std::function<SubTask *(WFRepeaterTask *)> create)
	{
		this->create = std::move(create);
	}

	void set_callback(std::function<void (WFRepeaterTask *)> cb)
	{
		this->callback = std::move(cb);
	}

protected:
	virtual void dispatch()
	{
		SubTask *task = this->create(this);

		if (task)
		{
			series_of(this)->push_front(this);
			series_of(this)->push_front(task);
		}
		else
			this->state = WFT_STATE_SUCCESS;

		this->subtask_done();
	}

	virtual SubTask *done()
	{
		SeriesWork *series = series_of(this);

		if (this->state != WFT_STATE_UNDEFINED)
		{
			if (this->callback)
				this->callback(this);

			delete this;
		}

		return series->pop();
	}

protected:
	std::function<SubTask *(WFRepeaterTask *)> create;
	std::function<void (WFRepeaterTask *)> callback;

public:
	WFRepeaterTask(std::function<SubTask *(WFRepeaterTask *)>&& create,
				   std::function<void (WFRepeaterTask *)>&& cb) :
		create(std::move(create)),
		callback(std::move(cb))
	{
	}

protected:
	virtual ~WFRepeaterTask() { }
};

class WFModuleTask : public ParallelTask, protected SeriesWork
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
	SeriesWork *sub_series() { return this; }

	const SeriesWork *sub_series() const { return this; }

public:
	void *user_data;

public:
	void set_callback(std::function<void (const WFModuleTask *)> cb)
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
	SubTask *first;
	std::function<void (const WFModuleTask *)> callback;

public:
	WFModuleTask(SubTask *first,
				 std::function<void (const WFModuleTask *)>&& cb) :
		ParallelTask(&this->first, 1),
		SeriesWork(first, nullptr),
		callback(std::move(cb))
	{
		this->first = first;
		this->set_in_parallel(this);
		this->user_data = NULL;
	}

protected:
	virtual ~WFModuleTask()
	{
		if (!this->is_finished())
			this->dismiss_recursive();
	}
};

#include "WFTask.inl"

#endif


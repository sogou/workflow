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
          Xie Han (xiehan@sogou-inc.com)
*/

template<class MSG>
class WFChannelOutTask : public WFChannelTask<MSG>
{
public:
	virtual MSG *message_out()
	{
		return &this->msg;
	}

public:
	WFChannelOutTask(CommChannel *channel, CommScheduler *scheduler,
					 std::function<void (WFChannelTask<MSG> *)>&& cb) :
		WFChannelTask<MSG>(channel, scheduler, std::move(cb))
	{
	}

protected:
	virtual ~WFChannelOutTask() { }
};

template<class MSG>
class WFChannelInTask : public WFChannelTask<MSG>
{
protected:
	virtual void dispatch()
	{
		this->state = WFT_STATE_SUCCESS;
		this->error = 0;
		this->process(this);
		this->subtask_done();
	}

public:
	WFChannelInTask(CommChannel *channel, CommScheduler *scheduler,
					std::function<void (WFChannelTask<MSG> *)>& proc) :
		WFChannelTask<MSG>(channel, scheduler, nullptr),
		process(proc)
	{
	}

protected:
	std::function<void (WFChannelTask<MSG> *)>& process;

protected:
	virtual ~WFChannelInTask() { }
};

template<class MSG>
class WFChannel : public ChanRequest
{
public:
	int get_state() const { return this->state; }
	int get_error() const { return this->error; }
	bool is_established() const { return this->established; }

	void set_callback(std::function<void (WFChannel<MSG> *)>&& cb)
	{
		this->callback = std::move(cb);
	}

protected:
	virtual CommMessageIn *message_in()
	{
		this->session = this->new_session();
		return this->session->get_msg();
	}

	virtual WFChannelTask<MSG> *new_session()
	{
		auto *task = new WFChannelInTask<MSG>(this, this->scheduler,
											  this->process);
		Workflow::create_series_work(task, nullptr);
		return task;
	}

	virtual void handle_in(CommMessageIn *in)
	{
		if (this->session)
			this->session->dispatch();
		this->session = NULL;
	}

	virtual SubTask *done()
	{
		if (this->callback)
			this->callback(this);

		return series_of(this)->pop();
	}

protected:
	std::function<void (WFChannelTask<MSG> *)> process;
	std::function<void (WFChannel<MSG> *)> callback;

private:
	WFChannelTask<MSG> *session;

public:
	WFChannel(CommSchedObject *object, CommScheduler *scheduler,
			  std::function<void (WFChannelTask<MSG> *)>&& process) :
		ChanRequest(object, scheduler),
		process(std::move(process))
	{
		this->session = NULL;
	}

protected:
	virtual ~WFChannel() { }
};


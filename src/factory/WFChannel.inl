template<class MSG>
class WFChannelOutTask : public WFChannelTask<MSG>
{
public:
	WFChannelOutTask(CommChannel *channel, CommScheduler *scheduler,
				   std::function<void (WFChannelTask<MSG> *)>&& cb) :
		WFChannelTask<MSG>(channel, scheduler, std::move(cb))
	{
	}

	virtual MSG *msg_out()
	{
		return &this->msg;
	}
};

template<class MSG>
class WFChannelInTask : public WFChannelTask<MSG>
{
public:
	WFChannelInTask(CommChannel *channel, CommScheduler *scheduler,
				std::function<void (WFChannelTask<MSG> *)>& proc) :
		WFChannelTask<MSG>(channel, scheduler, nullptr),
		process(proc)
	{
	}

	virtual void dispatch()
	{
		this->state = WFT_STATE_SUCCESS;
		this->error = 0;
		this->process(this);
		this->subtask_done();
	}

protected:
	std::function<void (WFChannelTask<MSG> *)>& process;
};

template<class MSG>
class WFChannel : public ChanRequest
{
public:
	WFChannel(CommSchedObject *object, CommScheduler *scheduler,
			  std::function<void (WFChannelTask<MSG> *)>&& process) :
		ChanRequest(object, scheduler),
		process(std::move(process))
	{
		this->session = NULL;
	}

	virtual CommMessageIn *message_in()
	{
		this->session = this->new_session();
		return this->session->get_msg();
	}

	int get_state() const { return this->state; }
	int get_error() const { return this->error; }
	bool is_established() const { return this->established == 1; }
	void set_callback(std::function<void (WFChannel<MSG> *)>&& cb)
	{
		this->callback = std::move(cb);
	}

protected:
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
};


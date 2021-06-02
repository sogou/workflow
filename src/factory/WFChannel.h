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

#ifndef _WFCHANNEL_H_
#define _WFCHANNEL_H_

#include "CommScheduler.h"
#include "TransRequest.h"
#include "Workflow.h"
#include "WebSocketMessage.h"

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

protected:
	virtual ~WFChannelTask() { }
};

using WFWebSocketTask = WFChannelTask<protocol::WebSocketFrame>;
using websocket_callback_t = std::function<void (WFWebSocketTask *)>;
using websocket_process_t = std::function<void (WFWebSocketTask *)>;


#include "WFChannel.inl"

#endif


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
*/

#ifndef _WFWEBSOCKETCLIENT_H_
#define _WFWEBSOCKETCLIENT_H_

#include <string>
#include <functional>
#include "WFGlobal.h"
#include "HttpUtil.h"
#include "HttpMessage.h"
#include "WFChannel.h"
#include "WebSocketMessage.h"

struct WFWebSocketParams
{
	int idle_timeout;
	int ping_interval;
	bool random_masking_key;
};

static constexpr struct WFWebSocketParams WEBSOCKET_PARAMS_DEFAULT =
{
	.idle_timeout = WS_HANDSHAKE_TIMEOUT,
	.ping_interval = -1,
	.random_masking_key = false,
};

class WebSocketClient
{
public:
	int init(const std::string& url);
	WFWebSocketTask *create_websocket_task(websocket_callback_t cb);
	void deinit();

private:
	ComplexWebSocketChannel *channel;
	struct WFWebSocketParams params;
	void channel_callback(WFChannel<protocol::WebSocketFrame> *channel);

public:
	WebSocketClient(const struct WFWebSocketParams *params,
					websocket_process_t process);
	WebSocketClient(websocket_process_t process);
};

inline WFWebSocketTask *WebSocketClient::create_websocket_task(websocket_callback_t cb)
{
	return new ComplexWebSocketOutTask(this->channel, WFGlobal::get_scheduler(),
									   std::move(cb));
}

inline int WebSocketClient::init(const std::string& url)
{
	ParsedURI uri;
	if (URIParser::parse(url, uri) != 0)
		return -1;

	this->channel->set_uri(uri);
	return 0;
}

void WebSocketClient::deinit()
{
	WFWebSocketTask *task = NULL;

	pthread_mutex_lock(&this->channel->mutex);
	if (this->channel->is_established())
	{
			task = this->create_websocket_task(
			[](WFWebSocketTask *task){
/*
				ComplexWebSocketChannel *channel = (ComplexWebSocketChannel *)task->user_data;
				if (task->get_state() == WFT_STATE_SUCCESS &&
					channel->is_established())
				{
					Workflow::start_series_work(channel, nullptr);
					channel->set_sending(true);
				}
*/			}
		);
		protocol::WebSocketFrame *msg = task->get_msg();
		msg->set_opcode(WebSocketFrameConnectionClose);
//		task->user_data = this->channel;
	}
	pthread_mutex_unlock(&this->channel->mutex);

	if (task)
		task->start();
}

WebSocketClient::WebSocketClient(const struct WFWebSocketParams *params,
								 websocket_process_t process)
{
	this->params = *params;
	this->channel = new ComplexWebSocketChannel(NULL, WFGlobal::get_scheduler(),
												std::move(process));
	this->channel->set_idle_timeout(this->params.idle_timeout);
	auto&& cb = std::bind(&WebSocketClient::channel_callback,
						  this, std::placeholders::_1);
	this->channel->set_callback(cb);
}

WebSocketClient::WebSocketClient(websocket_process_t process)
{
	this->params = WEBSOCKET_PARAMS_DEFAULT;
	this->channel = new ComplexWebSocketChannel(NULL, WFGlobal::get_scheduler(),
												std::move(process));
	this->channel->set_idle_timeout(this->params.idle_timeout);
	auto&& cb = std::bind(&WebSocketClient::channel_callback,
						  this, std::placeholders::_1);
	this->channel->set_callback(cb);
}

void WebSocketClient::channel_callback(WFChannel<protocol::WebSocketFrame> *channel)
{
	pthread_mutex_lock(&this->channel->mutex);
	if (this->channel->is_established() == 0)
	{
		this->channel->set_state(WFT_STATE_SYS_ERROR);
		this->channel->set_sending(false);
	}
	pthread_mutex_unlock(&this->channel->mutex);
}

#endif


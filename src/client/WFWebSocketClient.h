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
	WFWebSocketTask *create_close_task(websocket_callback_t cb);

private:
	ComplexWebSocketChannel *channel;
	struct WFWebSocketParams params;

public:
	WebSocketClient(const struct WFWebSocketParams *params,
					websocket_process_t process);
	WebSocketClient(websocket_process_t process) :
		WebSocketClient(&WEBSOCKET_PARAMS_DEFAULT, std::move(process))
	{ }
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

inline WFWebSocketTask *WebSocketClient::create_close_task(websocket_callback_t cb)
{
	ComplexWebSocketOutTask *close_task;
	close_task = new ComplexWebSocketOutTask(this->channel,
											 WFGlobal::get_scheduler(),
											 std::move(cb));
	protocol::WebSocketFrame *msg = close_task->get_msg();
	msg->set_opcode(WebSocketFrameConnectionClose);
	return close_task;
}

WebSocketClient::WebSocketClient(const struct WFWebSocketParams *params,
								 websocket_process_t process)
{
	this->params = *params;
	this->channel = new ComplexWebSocketChannel(NULL, WFGlobal::get_scheduler(),
												std::move(process));
	this->channel->set_idle_timeout(this->params.idle_timeout);

	this->channel->set_callback([this](WFChannel<protocol::WebSocketFrame> *channel)
	{
		pthread_mutex_lock(&this->channel->mutex);
		if (this->channel->is_established() == 0)
		{
			this->channel->set_state(WFT_STATE_SYS_ERROR);
			this->channel->set_sending(false);
		}
		pthread_mutex_unlock(&this->channel->mutex);
	});
}

#endif


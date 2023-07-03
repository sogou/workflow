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
#include "HttpUtil.h"
#include "HttpMessage.h"
#include "WFChannel.h"
#include "WebSocketMessage.h"

struct WFWebSocketParams
{
	const char *url;
	int idle_timeout;
	int keep_alive_timeout;
	int ping_interval;
	size_t size_limit;
	bool random_masking_key;
	const char *sec_protocol;
	const char *sec_version;
};

static constexpr struct WFWebSocketParams WEBSOCKET_PARAMS_DEFAULT =
{
	.url				=	NULL,
	.idle_timeout		=	WS_HANDSHAKE_TIMEOUT,
	.keep_alive_timeout	=	-1,
	.ping_interval		=	-1,
	.size_limit			=	(size_t)-1,
	.random_masking_key	=	true,
	.sec_protocol		=	NULL,
	.sec_version		=	NULL,
};

class WebSocketClient
{
public:
	using websocket_close_t = std::function<void ()>;

	int init(const std::string& url);
	int init(const struct WFWebSocketParams *params);
	void deinit();

	WFWebSocketTask *create_websocket_task(websocket_callback_t cb);
	WFWebSocketTask *create_ping_task(websocket_callback_t cb);
	WFWebSocketTask *create_close_task(websocket_callback_t cb);

private:
	void channel_callback(WFChannel<protocol::WebSocketFrame> *channel,
						  websocket_close_t close);

private:
	ComplexWebSocketChannel *channel;
	websocket_process_t process;
	websocket_close_t close;

public:
	WebSocketClient(websocket_process_t process) :
		process(std::move(process)),
		close(nullptr)
	{ }

	 WebSocketClient(websocket_process_t process,
					 websocket_close_t close) :
		process(std::move(process)),
		close(std::move(close))
	{ }

	virtual ~WebSocketClient() { }
};

#endif


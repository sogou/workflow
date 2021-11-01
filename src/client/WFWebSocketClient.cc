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

#include "WFChannel.h"
#include "HttpMessage.h"
#include "WebSocketMessage.h"
#include "WFWebSocketClient.h"

WFWebSocketTask *WebSocketClient::create_websocket_task(websocket_callback_t cb)
{
	return new ComplexWebSocketOutTask(&this->channel, WFGlobal::get_scheduler(),
									   std::move(cb));
}

int WebSocketClient::init(const std::string& url)
{
	ParsedURI uri;

	if (pthread_cond_init(&this->shutdown_cond, NULL) == 0)
	{
		if (URIParser::parse(url, uri) == 0)
		{
			this->channel.set_uri(uri);
			return 0;
		}

		pthread_cond_destroy(&this->shutdown_cond);
	}

	return -1;
}

void WebSocketClient::deinit()
{
	pthread_mutex_lock(&this->channel.mutex);

	while (this->channel.get_sending())
		pthread_cond_wait(&this->shutdown_cond, &this->channel.mutex);

	pthread_mutex_unlock(&this->channel.mutex);
	pthread_cond_destroy(&this->shutdown_cond);
}

WFWebSocketTask *WebSocketClient::create_ping_task(websocket_callback_t cb)
{
	ComplexWebSocketOutTask *ping_task;
	ping_task = new ComplexWebSocketOutTask(&this->channel,
											WFGlobal::get_scheduler(),
											std::move(cb));

	protocol::WebSocketFrame *msg = ping_task->get_msg();
	msg->set_opcode(WebSocketFramePing);

	return ping_task;
}

WFWebSocketTask *WebSocketClient::create_close_task(websocket_callback_t cb)
{
	ComplexWebSocketOutTask *close_task;
	close_task = new ComplexWebSocketOutTask(&this->channel,
											 WFGlobal::get_scheduler(),
											 std::move(cb));

	protocol::WebSocketFrame *msg = close_task->get_msg();
	msg->set_opcode(WebSocketFrameConnectionClose);

	return close_task;
}

WebSocketClient::WebSocketClient(const struct WFWebSocketParams *params,
								 websocket_process_t process) :
	channel(NULL, WFGlobal::get_scheduler(), std::move(process))
{
	this->params = *params;
	this->channel.set_idle_timeout(this->params.idle_timeout);
	this->channel.set_size_limit(this->params.size_limit);

	this->channel.set_callback([this](WFChannel<protocol::WebSocketFrame> *channel)
	{
		pthread_mutex_lock(&this->channel.mutex);

		if (this->channel.is_established() == 0)
			this->channel.set_sending(false);

		this->channel.condition.signal(NULL);
		pthread_cond_signal(&this->shutdown_cond);

		pthread_mutex_unlock(&this->channel.mutex);
	});
}


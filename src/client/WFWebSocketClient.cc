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

#include "HttpMessage.h"
#include "WFChannel.h"
#include "WebSocketMessage.h"
#include "WFWebSocketClient.h"

WFWebSocketTask *WebSocketClient::create_websocket_task(websocket_callback_t cb)
{
	WFWebSocketTask *task = new ComplexWebSocketOutTask(this->channel,
														WFGlobal::get_scheduler(),
														std::move(cb));

	task->get_msg()->set_masking_key(this->channel->gen_masking_key());
	return task;
}

int WebSocketClient::init(const std::string& url)
{
	struct WFWebSocketParams params = WEBSOCKET_PARAMS_DEFAULT;
	params.url = url.c_str();
	return this->init(&params);
}

int WebSocketClient::init(const struct WFWebSocketParams *params)
{
	ParsedURI uri;
	if (URIParser::parse(params->url, uri) < 0)
		return -1;

	this->channel = new ComplexWebSocketChannel(NULL,
												WFGlobal::get_scheduler(),
												params->random_masking_key,
												this->process);
	this->channel->set_uri(uri);
	this->channel->set_idle_timeout(params->idle_timeout);
	this->channel->set_size_limit(params->size_limit);
	if (uri.scheme && strcasecmp(uri.scheme, "wss") == 0)
		this->channel->set_transport_type(TT_TCP_SSL);

	if (params->sec_protocol)
		this->channel->set_sec_protocol(params->sec_protocol);
	if (params->sec_version)
	this->channel->set_sec_version(params->sec_version);

	auto&& cb = std::bind(&WebSocketClient::channel_callback, this,
						  std::placeholders::_1, this->close);
	this->channel->set_callback(cb);

	return 0;
}

void WebSocketClient::deinit()
{
	SeriesWork *series;
	this->channel->set_pointer(NULL);
	series = Workflow::create_series_work(this->channel,
										  [](const SeriesWork *series){
		ComplexWebSocketChannel *channel;
		channel = (ComplexWebSocketChannel *)series->get_context();
		delete channel;
	});

	series->set_context(this->channel);
	series->start();
}

WFWebSocketTask *WebSocketClient::create_ping_task(websocket_callback_t cb)
{
	ComplexWebSocketOutTask *ping_task;
	ping_task = new ComplexWebSocketOutTask(this->channel,
											WFGlobal::get_scheduler(),
											std::move(cb));

	protocol::WebSocketFrame *msg = ping_task->get_msg();
	msg->set_opcode(WebSocketFramePing);
	msg->set_masking_key(this->channel->gen_masking_key());

	return ping_task;
}

WFWebSocketTask *WebSocketClient::create_close_task(websocket_callback_t cb)
{
	ComplexWebSocketOutTask *close_task;
	close_task = new ComplexWebSocketOutTask(this->channel,
											 WFGlobal::get_scheduler(),
											 std::move(cb));

	protocol::WebSocketFrame *msg = close_task->get_msg();
	msg->set_opcode(WebSocketFrameConnectionClose);
	msg->set_masking_key(this->channel->gen_masking_key());

	return close_task;
}

void WebSocketClient::channel_callback(WFChannel<protocol::WebSocketFrame> *ch,
									   std::function<void ()> close)
{
	ComplexWebSocketChannel *channel = (ComplexWebSocketChannel *)ch;

	pthread_mutex_lock(&channel->mutex);
	if (channel->is_established() == 0)
	{
		channel->set_state(WFT_STATE_SYS_ERROR);
		channel->set_sending(false);
		if (close != nullptr)
			close();
	}
	pthread_mutex_unlock(&channel->mutex);
}


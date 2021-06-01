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

#include "WFTask.h"
#include "WFGlobal.h"
#include "WebSocketTask.h"

#define WS_HTTP_SEC_KEY_K		"Sec-WebSocket-Key"
#define WS_HTTP_SEC_KEY_V		"dGhlIHNhbXBsZSBub25jZQ=="
#define WS_HTTP_SEC_PROTOCOL_K	"Sec-WebSocket-Protocol"
#define WS_HTTP_SEC_PROTOCOL_V	"chat"
#define WS_HTTP_SEC_VERSION_K	"Sec-WebSocket-Version"
#define WS_HTTP_SEC_VERSION_V	"13"

using namespace protocol;

class WebSocketInTask : public WFChannelInTask<WebSocketFrame>
{
public:
	WebSocketInTask(CommChannel *channel, CommScheduler *scheduler,
					websocket_process_t& proc) :
	WFChannelInTask<WebSocketFrame>(channel, scheduler, proc)
	{}

protected:
	virtual void dispatch();
	virtual SubTask *done();
};

void WebSocketInTask::dispatch()
{
	const websocket_parser_t *parser = this->get_msg()->get_parser();
	
	if (parser->opcode != WebSocketFrameConnectionClose &&
		parser->status_code != WSStatusCodeUndefined)
	{
		this->state = WFT_STATE_SYS_ERROR;
		this->error = parser->status_code;
	}
	else
	{
		this->state = WFT_STATE_SUCCESS;
		this->error = 0;
	}

	this->process(this);
	this->subtask_done();
}

SubTask *WebSocketInTask::done()
{
	SeriesWork *series = series_of(this);
	const websocket_parser_t *parser = this->get_msg()->get_parser();
	WebSocketChannel *channel = static_cast<WebSocketChannel *>(this->get_request_channel());

	if ((parser->opcode == WebSocketFrameConnectionClose && !channel->is_established()) ||
		parser->status_code != WSStatusCodeUndefined)
	{
		WebSocketTask *close_task = new WebSocketTask(channel,
													  WFGlobal::get_scheduler(),
													  nullptr);
		WebSocketFrame *msg = close_task->get_msg();
		msg->set_opcode(WebSocketFrameConnectionClose);
		msg->set_data(parser);
		series->push_front(close_task);
	}
	else if (parser->opcode == WebSocketFramePing)
	{
		WebSocketTask *pong_task = new WebSocketTask(channel,
													 WFGlobal::get_scheduler(),
													 nullptr);
		WebSocketFrame *msg = pong_task->get_msg();
		msg->set_opcode(WebSocketFramePong);
		msg->set_data(parser);
		series->push_front(pong_task);
	}

	if (this->callback)
		this->callback(this);

	delete this;
	return series->pop();
}

SubTask *WebSocketTask::upgrade()
{
	WFChannelOutTask<HttpRequest> *http_task;
	auto&& cb = std::bind(&WebSocketTask::http_callback,
						  this, std::placeholders::_1);

	WebSocketChannel *channel = static_cast<WebSocketChannel *>(this->get_request_channel());

	http_task = new WFChannelOutTask<HttpRequest>(this->channel,
												WFGlobal::get_scheduler(),
												cb);
	HttpRequest *req = http_task->get_msg();
	req->set_method(HttpMethodGet);
	req->set_http_version("HTTP/1.1");
	req->set_request_uri("/");
	req->add_header_pair("Host", channel->get_uri()->host);
	req->add_header_pair("Upgrade", "websocket");
	req->add_header_pair("Connection", "Upgrade");
	req->add_header_pair(WS_HTTP_SEC_KEY_K, WS_HTTP_SEC_KEY_V);
	req->add_header_pair(WS_HTTP_SEC_PROTOCOL_K, WS_HTTP_SEC_PROTOCOL_V);
	req->add_header_pair(WS_HTTP_SEC_VERSION_K, WS_HTTP_SEC_VERSION_V);

	return http_task;
}

void WebSocketTask::http_callback(WFChannelTask<HttpRequest> *task)
{
	if (task->get_state() == WFT_STATE_SYS_ERROR)
	{
		this->state = WFT_STATE_SYS_ERROR;
		this->error = task->get_error();
	}

	this->ready = true;
}

CommMessageIn *WebSocketChannel::message_in()
{
	if (this->state == WFT_STATE_UNDEFINED)
		return new HttpResponse;

	return WFWebSocketChannel::message_in();
}

void WebSocketChannel::handle_in(CommMessageIn *in)
{
	bool parse_websocket = false;

	pthread_mutex_lock(&this->mutex);

	if (this->state == WFT_STATE_UNDEFINED)
	{
		HttpResponse *resp = static_cast<HttpResponse *>(in);

		if (strcmp(resp->get_status_code(), "101") == 0)
			this->state = WFT_STATE_SUCCESS;
		else
			this->state = WFT_STATE_TASK_ERROR;

		delete resp;

		this->sending = false;
	}
	else if (this->state == WFT_STATE_SUCCESS)
		parse_websocket = true;

	pthread_mutex_unlock(&this->mutex);

	if (!parse_websocket) // so this is equal to should_count
	{
		WebSocketChannel *channel = static_cast<WebSocketChannel *>(this);
		pthread_mutex_lock(&channel->mutex);
		channel->condition.signal();
		pthread_mutex_unlock(&channel->mutex);
		return;
	}

	WFWebSocketChannel::handle_in(in);
}

int WebSocketChannel::first_timeout()
{
	return this->idle_timeout;
}

WFWebSocketTask *WebSocketChannel::new_session()
{
	auto *task = new WebSocketInTask(this, this->scheduler,
									 this->process);
	Workflow::create_series_work(task, nullptr);
	return task;
}


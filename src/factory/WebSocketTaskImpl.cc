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
#include "WFChannel.h"

#define WS_HTTP_SEC_KEY_K		"Sec-WebSocket-Key"
#define WS_HTTP_SEC_KEY_V		"dGhlIHNhbXBsZSBub25jZQ=="

#define WS_HTTP_SEC_PROTOCOL_K	"Sec-WebSocket-Protocol"
#define WS_HTTP_SEC_PROTOCOL_V	"chat"

#define WS_HTTP_SEC_VERSION_K	"Sec-WebSocket-Version"
#define WS_HTTP_SEC_VERSION_V	"13"

#define WS_HTTP_SEC_ACCEPT_K	"Sec-WebSocket-Accept"
#define WS_HTTP_SEC_ACCEPT_V	"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

using namespace protocol;

class ComplexWebSocketInTask : public WFChannelInTask<WebSocketFrame>
{
protected:
	virtual void dispatch();
	virtual SubTask *done();

public:
	ComplexWebSocketInTask(ComplexWebSocketChannel *channel,
						   CommScheduler *scheduler,
						   websocket_process_t& proc) :
		WFChannelInTask<WebSocketFrame>(channel, scheduler, proc)
	{
	}
};

void ComplexWebSocketInTask::dispatch()
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
		this->process(this);
	}

	this->subtask_done();
}

SubTask *ComplexWebSocketInTask::done()
{
	SeriesWork *series = series_of(this);
	const websocket_parser_t *parser = this->get_msg()->get_parser();
	auto *channel = (ComplexWebSocketChannel *)this->get_request_channel();

	if ((parser->opcode == WebSocketFrameConnectionClose &&
		!channel->is_established()) ||
		parser->status_code != WSStatusCodeUndefined)
	{
		auto *close_task = new ComplexWebSocketOutTask(channel,
													   WFGlobal::get_scheduler(),
													   nullptr);
		WebSocketFrame *msg = close_task->get_msg();
		msg->set_opcode(WebSocketFrameConnectionClose);
		msg->set_data(parser);
		msg->set_masking_key(channel->gen_masking_key());
		series->push_front(close_task);
	}
	else if (parser->opcode == WebSocketFramePing)
	{
		auto *pong_task = new ComplexWebSocketOutTask(channel,
													  WFGlobal::get_scheduler(),
													  nullptr);
		WebSocketFrame *msg = pong_task->get_msg();
		msg->set_opcode(WebSocketFramePong);
		msg->set_data(parser);
		msg->set_masking_key(channel->gen_masking_key());
		series->push_front(pong_task);
	}

	if (this->callback)
		this->callback(this);

	delete this;
	return series->pop();
}

SubTask *ComplexWebSocketOutTask::done()
{
	auto *channel = (ComplexWebSocketChannel *)this->get_request_channel();

	if (channel->get_state() == WFT_STATE_UNDEFINED ||
		channel->get_state() == WFT_STATE_SUCCESS)
	{
		if (this->ready != true)
			return series_of(this)->pop();
	}
	else
	{
		this->state = channel->get_state();
		this->error = channel->get_error();
	}

	pthread_mutex_lock(&channel->mutex);
	channel->set_sending(false);
	channel->condition.signal(NULL);
	pthread_mutex_unlock(&channel->mutex);

	return WFChannelOutTask<WebSocketFrame>::done();
}

SubTask *ComplexWebSocketOutTask::upgrade()
{
	auto *channel = (ComplexWebSocketChannel *)this->get_request_channel();
	const ParsedURI *uri = channel->get_uri();
	std::string request_uri;

	auto *http_task = new WFChannelOutTask<HttpRequest>(this->channel,
														WFGlobal::get_scheduler(),
														[this](WFChannelTask<HttpRequest> *upgrade_task)
	{
		WFMailboxTask *waiter;
		ComplexWebSocketChannel *channel;
		channel = (ComplexWebSocketChannel *)this->get_request_channel();

		if (upgrade_task->get_state() == WFT_STATE_SUCCESS)
		{
			waiter = WFCondTaskFactory::create_wait_task(&channel->condition,
														 nullptr);
			series_of(upgrade_task)->push_front(waiter);
			this->ready = true;
		}
		else
		{
			channel->set_state(WFT_STATE_SYS_ERROR);
			this->state = upgrade_task->get_state();
			this->error = upgrade_task->get_error();
		}
	});

	if (uri->path && uri->path[0])
		request_uri = uri->path;
	else
		request_uri = "/";

	HttpRequest *req = http_task->get_msg();
	req->set_method(HttpMethodGet);
	req->set_http_version("HTTP/1.1");
	req->set_request_uri(request_uri);
	req->add_header_pair("Host", channel->get_uri()->host);
	req->add_header_pair("Upgrade", "websocket");
	req->add_header_pair("Connection", "Upgrade");
	req->add_header_pair(WS_HTTP_SEC_KEY_K, WS_HTTP_SEC_KEY_V);
	req->add_header_pair(WS_HTTP_SEC_PROTOCOL_K, WS_HTTP_SEC_PROTOCOL_V);
	req->add_header_pair(WS_HTTP_SEC_VERSION_K, WS_HTTP_SEC_VERSION_V);

	if (channel->get_sec_protocol())
		req->add_header_pair(WS_HTTP_SEC_PROTOCOL_K, channel->get_sec_protocol());
	if (channel->get_sec_version())
		req->add_header_pair(WS_HTTP_SEC_VERSION_K, channel->get_sec_version());

	return http_task;
}

CommMessageIn *ComplexWebSocketChannel::message_in()
{
	if (this->state == WFT_STATE_UNDEFINED)
		return new HttpResponse;

	return WFComplexChannel<WebSocketFrame>::message_in();
}

void ComplexWebSocketChannel::handle_in(CommMessageIn *in)
{
	bool parse_websocket = false;

	pthread_mutex_lock(&this->mutex);

	if (this->state == WFT_STATE_UNDEFINED)
	{
		HttpResponse *resp = static_cast<HttpResponse *>(in);

		if (this->check_handshake(resp))
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
		pthread_mutex_lock(&this->mutex);
		this->condition.signal(NULL);
		pthread_mutex_unlock(&this->mutex);
		return;
	}

	WFComplexChannel<WebSocketFrame>::handle_in(in);
}

int ComplexWebSocketChannel::first_timeout()
{
	return this->idle_timeout;
}

WFWebSocketTask *ComplexWebSocketChannel::new_session()
{
	auto *task = new ComplexWebSocketInTask(this, this->scheduler,
											this->process);
	Workflow::create_series_work(task, nullptr);
	task->get_msg()->set_size_limit(this->size_limit);
	return task;
}

bool ComplexWebSocketChannel::check_handshake(const HttpResponse *resp)
{
	if (strcmp(resp->get_status_code(), "101"))
		return false;

	std::string name;
	std::string value;
	HttpHeaderCursor resp_cursor(resp);
	int flag = 0;

	while (resp_cursor.next(name, value) && flag != 7)
	{
		if (name.compare("Upgrade") == 0 && value.compare("websocket") == 0)
		{
			flag |= 1;
		}
		else if (name.compare("Connection") == 0 &&
				 value.compare("Upgrade") == 0)
		{
			flag |= (1 << 1);
		}
		else if (name.compare(WS_HTTP_SEC_ACCEPT_K) == 0 &&
				 value.compare(WS_HTTP_SEC_ACCEPT_V) == 0)
		{
			flag |= (1 << 2);
		}
	}

	return flag == 7;
}


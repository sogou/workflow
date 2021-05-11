#ifndef _WFWEBSOCKETCLIENT_H_
#define _WFWEBSOCKETCLIENT_H_

#include "ComplexChannel.h"
#include "HttpUtil.h"
#include "HttpMessage.h"
#include "WebSocketMessage.h"

using WFWebSocketTask = ChannelTask<protocol::WebSocketFrame>;
using WFWebSocketChannel = ComplexChannel<protocol::WebSocketFrame>;

using websocket_callback_t = std::function<void (WFWebSocketTask *)>;
using websocket_process_t = std::function<void (WFWebSocketTask *)>;

class WebSocketChannel : public WFWebSocketChannel
{
protected:
	WebSocketChannel(CommSchedObject *object, CommScheduler *scheduler,
					 std::function<void (ChannelOutTask<IN> *)>&& process) :
		ComplexChannel<WebSocketFrame>(object, scheduler, std::move(process))
	{
		this->counter = NULL;
	}

	virtual SubTask *done();
	void http_callback(ChannelTask<HttpRequest> *task);
	CommMessageIn *message_in();
	void handle_in(CommMessageIn *in);

private:
	WFCounterTask *counter;
};

class WebSocketClient
{
public:
	WebSocketClient(websocket_process_t&& process) :
		WebSocketChannel(NULL, WFGlobal::get_scheduler(), std::move(process))
	{
	}

	int init(const std::string& url)
	{
		if (url.find("ws://") != 0)
			url = "ws://" + url;

		if (URIParser::parse(url, this->uri) != 0)
			return -1;

		return 0;
	}

	WFWebSocketTask *create_websocket_task(websocket_callback_t&& cb)
	{
		return new ComplexChannelTask<protocol::WebSocketFrame>(this->channel,
																this->scheduler,
																std::move(cb));
	}

private:
	ParsedURI uri;
	WebSocketChannel channel;
};

#endif


#ifndef _WFWEBSOCKETCLIENT_H_
#define _WFWEBSOCKETCLIENT_H_

#include "ComplexChannel.h"
#include "WFGlobal.h"
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
					 websocket_process_t&& process) :
		ComplexChannel<protocol::WebSocketFrame>(object, scheduler,
												 std::move(process))
	{
		this->counter = NULL;
	}

	virtual SubTask *done();
	void http_callback(ChannelTask<protocol::HttpRequest> *task);
	CommMessageIn *message_in();
	void handle_in(CommMessageIn *in);

private:
	WFCounterTask *counter;
};

class WebSocketClient
{
public:
	WebSocketClient(websocket_process_t&& process) :
		channel(NULL, WFGlobal::get_scheduler(), std::move(process))
	{
	}

	int init(const std::string& url)
	{
		std::string tmp = url;
		if (tmp.find("ws://") != 0)
			tmp = "ws://" + tmp;

		ParsedURI uri;
		if (URIParser::parse(tmp, uri) != 0)
			return -1;

		this->channel.set_uri(uri);
		return 0;
	}

	WFWebSocketTask *create_websocket_task(websocket_callback_t&& cb)
	{
		return new ComplexChannelOutTask<protocol::WebSocketFrame>(&this->channel,
																   WFGlobal::get_scheduler(),
																   std::move(cb));
	}

private:
	WFWebSocketChannel channel;
};

#endif


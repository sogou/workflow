#ifndef _WFWEBSOCKETCLIENT_H_
#define _WFWEBSOCKETCLIENT_H_

#include "WFChannel.h"
#include "WebSocketMessage.h"

using WFWebSocketTask = ChannelTask<protocol::WebSocketFrame>;
using WFWebSocketChannel = WFChannel<protocol::WebSocketFrame,
									 protocol::WebSocketFrame>;

using websocket_callback_t = std::function<void (WFWebSocketTask *)>;
using websocket_process_t = std::function<void (WFWebSocketTask *)>;

class WebSocketClient : public WFWebSocketChannel
{
public:
	WebSocketClient()
	{
		this->counter = NULL;
	}

	int init(const std::string& url)
	{
		if (url.find("ws://") != 0)
			url = "ws://" + url;

		if (URIParser::parse(url, this->uri) != 0)
			return -1;

		return 0;
	}

	virtual void handle_established();
	virtual CommMessageIn *message_in();
	virtual void handle_in(CommMessageIn *in);
	virtual bool close(std::function<void ()> on_close);

	WFRouterTask *route();

private:
	void router_callback(WFRouterTask *task);
	void establish_callback(WFEstablishTask *task);
	void http_callback(ChannelTask<HttpRequest> *task);

private:
	ParsedURI uri;
	WFCounterTask *counter;
};

#endif


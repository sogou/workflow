#ifndef _WFCHANNELFACTORY_H_
#define _WFCHANNELFACTORY_H_

#include "WFChannel.h"
#include "WebSocketMessage.h"

using WFWebSocketTask = ChannelTask<protocol::WebSocketFrame>;
using WFWebSocketChannel = WFChannel<protocol::WebSocketFrame,
									 protocol::WebSocketFrame>;

using websocket_callback_t = std::function<void (WFWebSocketTask *)>;
using websocket_process_t = std::function<void (WFWebSocketTask *)>;

class WFChannelFactory
{
public:
	// to be static
	WFWebSocketChannel *create_websocket_channel(const struct sockaddr *addr,
												 socklen_t addrlen,
												 int connect_timeout,
												 websocket_process_t process);

public:
    int init(size_t threads)
    {   
        return this->communicator.init(threads, 1/*handler_threads*/);
    }   

    void deinit()
    {   
        this->communicator.deinit();
    }

	template<class IN, class OUT>
	WFChannel<IN, OUT> *create_channel(const struct sockaddr *addr, socklen_t addrlen,
									   int connect_timeout,
									   std::function<void (ChannelTask<IN> *)> process)
	{
		// TODO: reuse target
		CommTarget *target = new CommTarget();
		if (target)
		{
			if (target->init(addr, addrlen, connect_timeout, 0) >= 0)
			{
				auto *channel = new WFChannel<IN, OUT>(&this->communicator,
													   target,
													   std::move(process));
				if (channel)
					return channel;
			}
			else
				delete target;
		}
		return NULL;
	}

private:
	Communicator communicator;
};

#endif


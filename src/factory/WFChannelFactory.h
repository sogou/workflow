#ifndef _WFCHANNELFACTORY_H_
#define _WFCHANNELFACTORY_H_

#include "WFChannel.h"
#include "WebSocketMessage.h"

using WFWebSocketChannel = WFChannel<protocol::WebSocketMessage,
									 protocol::WebSocketMessage>;
using WFWebSocketTask = ChannelTask<protocol::WebSocketMessage>;
using websocket_callback_t = std::function<void (WFWebSocketTask *)>;
using websocket_process_t = std::function<void (WFWebSocketTask *)>;

class WFChannelFactory
{
public:
	static WFWebSocketChannel *create_websocket_channel(const struct sockaddr *addr,
														socklen_t addrlen,
														int connect_timeout,
														websocket_process_t process);

public:
    int init(size_t threads)
    {   
        return this->comm.init(threads, 1/*handler_threads*/);
    }   

    void deinit()
    {   
        this->comm.deinit();
    }

	template<class IN, class OUT>
	WFChannel<IN, OUT> *create_channel(const struct sockaddr *addr, socklen_t addrlen,
									   int connect_timeout, std::function<void (ChannelTask<IN> *)> process)
	{
		// TODO: reuse target
		CommTarget *target = new CommTarget();
		if (target)
		{
			if (target->init(addr, addrlen, connect_timeout, 0 /*response_timeout*/) >= 0)
			{
				auto *channel = new WFChannel<IN, OUT>(&this->comm, target, std::move(process));
				if (channel)
					return channel;
			}
			else
				delete target;
		}
		return NULL;
	}

private:
	Communicator comm;
//	std::map<int, CommTarget *> target_map;
};
/*
class WFChannelFactory
{
public:
};
*/
#endif

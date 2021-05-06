#include "workflow/WFFacilities.h"
#include "workflow/WFChannelFactory.h"

#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include "unistd.h"

#define CONNECT_TIMEOUT 10000

using namespace protocol;

struct addr_info
{
    struct sockaddr_storage ss; 
    unsigned int ss_len;
};

int get_addr_info(const char *ip, const char *port, struct addr_info *ai)
{
    struct addrinfo hints = { 0 };
    struct addrinfo *res;
    int gai_err;

    hints.ai_socktype = SOCK_STREAM;
    gai_err = getaddrinfo(ip, port, &hints, &res);

    if (!gai_err)
    {   
        memset(ai, 0, sizeof(struct addr_info));
        memcpy(&ai->ss, res->ai_addr, res->ai_addrlen);
        ai->ss_len = res->ai_addrlen;
        freeaddrinfo(res);
    }   

    return gai_err;
}

void process_message(WFWebSocketTask *task)
{
	WebSocketMessage *msg = task->get_message();
	fprintf(stderr, "process_message() opcode=%d\n", msg->get_opcode());
}

int main(int argc, const char *argv[])
{
	if (argc != 3)
	{
		fprintf(stderr, "[USAGE] %s IP PORT\n", argv[0]);
		return 0;
	}

	WFChannelFactory factory;

	if (factory.init(4) < 0)
	{
		fprintf(stderr, "failed to create factory\n");
		return 0;
	}

	const char *ip = argv[1];
    const char *port = argv[2];
	struct addr_info ai;
	if (get_addr_info(ip, port, &ai) != 0)
	{
		fprintf(stderr, "failed to parse remote ip:port = %s:%s\n", ip, port);
		return 0;
	}

	auto *channel = factory.create_websocket_channel((struct sockaddr*) &ai.ss,
													 ai.ss_len,
													 CONNECT_TIMEOUT,
													 process_message);
	if (!channel)
	{
		fprintf(stderr, "failed to create channel\n");
		return 0;
	}

	WFFacilities::WaitGroup wait_group(1);
	channel->connect([&wait_group, &ip, &port, &channel]()
	{
		fprintf(stderr, "channel connected. ip=%s port=%s state=%d\n",
				ip, port, channel->get_state());

		if (channel->get_state() == CHANNEL_STATE_ESTABLISHED)
		{
			auto *ping_task = channel->create_out_task([&wait_group, &channel]
													   (WFWebSocketTask *task)
			{
				fprintf(stderr, "PING task on_send() state=%d error=%d\n",
						task->get_state(), task->get_error());

				auto *text_task = channel->create_out_task([&wait_group]
														   (WFWebSocketTask *task)
				{
					fprintf(stderr, "TEXT task on_send() state=%d error=%d\n",
							task->get_state(), task->get_error());
					wait_group.done();
				});

				WebSocketMessage *msg = text_task->get_message();
				msg->set_masking_key(1412);
				msg->set_text_data("xiehan", 6, true);
				text_task->start();
			});

			WebSocketMessage *msg = ping_task->get_message();
			msg->set_opcode(WebSocketFramePing);
			msg->set_masking_key(0);
			ping_task->start();
		}
		else
			wait_group.done();
	});
		
	wait_group.wait();

	sleep(5);
	channel->close(nullptr);
	sleep(2);
	factory.deinit();

	return 0;
}


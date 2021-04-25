#include "workflow/HttpMessage.h"
#include "workflow/HttpUtil.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/WFFacilities.h"
#include "workflow/WFChannel.h"

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

#include <sys/socket.h>

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

void process_message(ChannelTask<protocol::HttpResponse> *task)
{
	fprintf(stderr, "process_message() state=%d error=%d\n",
			task->get_state(), task->get_error());

	protocol::HttpResponse *resp= task->get_message();
	fprintf(stderr, "%s %s %s\r\n", resp->get_http_version(),
									resp->get_status_code(),
									resp->get_reason_phrase());

	std::string name;
	std::string value;
	protocol::HttpHeaderCursor resp_cursor(resp);
	while (resp_cursor.next(name, value))
		fprintf(stderr, "%s: %s\r\n", name.c_str(), value.c_str());
	fprintf(stderr, "\r\n");

	/* Print response body. */
	const void *body;
	size_t body_len;

	resp->get_parsed_body(&body, &body_len);
	fwrite(body, 1, body_len, stdout);
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

	auto *channel = factory.create_channel<protocol::HttpResponse,
										   protocol::HttpRequest>((struct sockaddr*) &ai.ss,
																   ai.ss_len,
																   CONNECT_TIMEOUT,
																   process_message);
	if (!channel)
	{
		fprintf(stderr, "failed to create channel\n");
		return 0;
	}

	WFFacilities::WaitGroup wait_group(1);
	channel->connect([&wait_group, &ip, &port, &channel]() {
		fprintf(stderr, "channel to %s:%s connected! state=%d\n",
				ip, port, channel->get_state());
		if (channel->get_state() == CHANNEL_STATE_ESTABLISHED)
		{
			auto *task = channel->create_out_task([&wait_group](ChannelTask<protocol::HttpRequest> *task){
				fprintf(stderr, "send. state=%d error=%d\n",
						task->get_state(), task->get_error());
				wait_group.done();
			});

			protocol::HttpRequest *req = task->get_message();
			req->set_method(HttpMethodGet);
			req->set_http_version("HTTP/1.1");
			req->set_request_uri("/");
			req->set_header_pair("Host", "");
			req->add_header_pair("Accept", "*/*");
			req->add_header_pair("User-Agent", "Wget/1.14 (linux-gnu)");
			task->start();
		}
		else
			wait_group.done();
	});

	wait_group.wait();

	channel->close(nullptr);
	sleep(2);

	factory.deinit();

	return 0;
}


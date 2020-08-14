/*
  Copyright (c) 2019 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

	  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Xie Han (xiehan@sogou-inc.com;63350856@qq.com)
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "workflow/HttpMessage.h"
#include "workflow/HttpUtil.h"
#include "workflow/WFServer.h"
#include "workflow/WFHttpServer.h"
#include "workflow/WFFacilities.h"

void process(WFHttpTask *server_task)
{
	protocol::HttpRequest *req = server_task->get_req();
	protocol::HttpResponse *resp = server_task->get_resp();
	long long seq = server_task->get_task_seq();
	protocol::HttpHeaderCursor cursor(req);
	std::string name;
	std::string value;
	char buf[8192];
	int len;

	/* Set response message body. */
	resp->append_output_body_nocopy("<html>", 6);
	len = snprintf(buf, 8192, "<p>%s %s %s</p>", req->get_method(),
				   req->get_request_uri(), req->get_http_version());
	resp->append_output_body(buf, len);

	while (cursor.next(name, value))
	{
		len = snprintf(buf, 8192, "<p>%s: %s</p>", name.c_str(), value.c_str());
		resp->append_output_body(buf, len);
	}

	resp->append_output_body_nocopy("</html>", 7);

	/* Set status line if you like. */
	resp->set_http_version("HTTP/1.1");
	resp->set_status_code("200");
	resp->set_reason_phrase("OK");

	resp->add_header_pair("Content-Type", "text/html");
	resp->add_header_pair("Server", "Sogou WFHttpServer");
	if (seq == 9) /* no more than 10 requests on the same connection. */
		resp->add_header_pair("Connection", "close");

	/* print some log */
	char addrstr[128];
	struct sockaddr_storage addr;
	socklen_t l = sizeof addr;
	unsigned short port = 0;

	server_task->get_peer_addr((struct sockaddr *)&addr, &l);
	if (addr.ss_family == AF_INET)
	{
		struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
		inet_ntop(AF_INET, &sin->sin_addr, addrstr, 128);
		port = ntohs(sin->sin_port);
	}
	else if (addr.ss_family == AF_INET6)
	{
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
		inet_ntop(AF_INET6, &sin6->sin6_addr, addrstr, 128);
		port = ntohs(sin6->sin6_port);
	}
	else
		strcpy(addrstr, "Unknown");

	fprintf(stderr, "Peer address: %s:%d, seq: %lld.\n",
			addrstr, port, seq);
}

static WFFacilities::WaitGroup wait_group(1);

void sig_handler(int signo)
{
	wait_group.done();
}

int main(int argc, char *argv[])
{
	unsigned short port;

	if (argc != 2)
	{
		fprintf(stderr, "USAGE: %s <port>\n", argv[0]);
		exit(1);
	}

	signal(SIGINT, sig_handler);

	WFHttpServer server(process);
	port = atoi(argv[1]);
	if (server.start(port) == 0)
	{
		wait_group.wait();
		server.stop();
	}
	else
	{
		perror("Cannot start server");
		exit(1);
	}

	return 0;
}


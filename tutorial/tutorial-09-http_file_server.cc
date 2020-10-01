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

#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <utility>
#include <string>
#include "workflow/HttpMessage.h"
#include "workflow/WFHttpServer.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/Workflow.h"
#include "workflow/WFFacilities.h"

using namespace protocol;

void pread_callback(WFFileIOTask *task)
{
	FileIOArgs *args = task->get_args();
	long ret = task->get_retval();
	HttpResponse *resp = (HttpResponse *)task->user_data;

	close(args->fd);
	if (task->get_state() != WFT_STATE_SUCCESS || ret < 0)
	{
		resp->set_status_code("503");
		resp->append_output_body("<html>503 Internal Server Error.</html>");
	}
	else /* Use '_nocopy' carefully. */
		resp->append_output_body_nocopy(args->buf, ret);
}

void process(WFHttpTask *server_task, const char *root)
{
	HttpRequest *req = server_task->get_req();
	HttpResponse *resp = server_task->get_resp();
	const char *uri = req->get_request_uri();
	const char *p = uri;

	printf("Request-URI: %s\n", uri);
	while (*p && *p != '?')
		p++;

	std::string abs_path(uri, p - uri);
	abs_path = root + abs_path;
	if (abs_path.back() == '/')
		abs_path += "index.html";

	resp->add_header_pair("Server", "Sogou C++ Workflow Server");

	int fd = open(abs_path.c_str(), O_RDONLY);
	if (fd >= 0)
	{
		size_t size = lseek(fd, 0, SEEK_END);
		void *buf = malloc(size); /* As an example, assert(buf != NULL); */
		WFFileIOTask *pread_task;

		pread_task = WFTaskFactory::create_pread_task(fd, buf, size, 0,
													  pread_callback);
		/* To implement a more complicated server, please use series' context
		 * instead of tasks' user_data to pass/store internal data. */
		pread_task->user_data = resp;	/* pass resp pointer to pread task. */
		server_task->user_data = buf;	/* to free() in callback() */
		server_task->set_callback([](WFHttpTask *t){ free(t->user_data); });
		series_of(server_task)->push_back(pread_task);
	}
	else
	{
		resp->set_status_code("404");
		resp->append_output_body("<html>404 Not Found.</html>");
	}
}

static WFFacilities::WaitGroup wait_group(1);

void sig_handler(int signo)
{
	wait_group.done();
}

int main(int argc, char *argv[])
{
	if (argc != 2 && argc != 3)
	{
		fprintf(stderr, "%s <port> [root path]\n",
				argv[0]);
		exit(1);
	}

	signal(SIGINT, sig_handler);

	unsigned short port = atoi(argv[1]);
	const char *root = (argc >= 3 ? argv[2] : ".");
	auto&& proc = std::bind(process, std::placeholders::_1, root);
	WFHttpServer server(proc);

	if (server.start(port) == 0)
	{
		wait_group.wait();
		server.stop();
	}
	else
	{
		perror("start server");
		exit(1);
	}

	return 0;
}


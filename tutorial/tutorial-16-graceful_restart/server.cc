/*
  Copyright (c) 2022 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Authors: Li Yingxin (liyingxin@sogou-inc.com)
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include "workflow/WFFacilities.h"
#include "workflow/WFHttpServer.h"

static WFFacilities::WaitGroup wait_group(1);

void sig_handler(int signo)
{
	wait_group.done();
}

int main(int argc, const char *argv[])
{
	if (argc != 3)
	{
		fprintf(stderr, "USAGE: %s listen_fd pipe_fd\n", argv[0]);
		exit(1);
	}

	int listen_fd = atoi(argv[1]);
	int pipe_fd = atoi(argv[2]);

	signal(SIGUSR1, sig_handler);

	WFHttpServer server([](WFHttpTask *task) {
     	task->get_resp()->append_output_body("<html>Hello World!</html>");
	});

	if (server.serve(listen_fd) == 0)
	{
		wait_group.wait();
		server.shutdown();
		write(pipe_fd, "success", strlen("success"));
		server.wait_finish();
	}
	else
		write(pipe_fd, "failed ", strlen("failed "));

	close(pipe_fd);
	close(listen_fd);
    return 0;
}


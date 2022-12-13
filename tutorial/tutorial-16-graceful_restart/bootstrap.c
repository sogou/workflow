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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>

int flag = 0;

void sig_handler(int signo)
{
	if (signo == SIGUSR1)
		flag = 1;
	else if (signo == SIGINT || signo == SIGTERM)
		flag = 2;
}

int main(int argc, const char *argv[])
{
	if (argc != 3)
	{
		fprintf(stderr, "USAGE: %s EXEC_PROCESS PORT\n"
				"Bootstrap for workflow server to restart gracefully.\n",
				argv[0]);
		exit(1);
	}

	unsigned short port = atoi(argv[2]);
	int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sin;

	memset(&sin, 0, sizeof sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(listen_fd, (struct sockaddr *)&sin, sizeof sin) < 0)
	{
		close(listen_fd);
		perror("bind error");
		exit(1);
	}

	pid_t pid;
	int pipe_fd[2];
	ssize_t len;
	char buf[100];
	int status;
	int ret;

	char listen_fd_str[10] = { 0 };
	char write_fd_str[10] = { 0 };
	sprintf(listen_fd_str, "%d", listen_fd);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGUSR1, sig_handler);

	while (flag < 2)
	{
		if (pipe(pipe_fd) == -1)
		{
			perror("open pipe error");
			exit(1);
		}

		memset(write_fd_str, 0, sizeof write_fd_str);
		sprintf(write_fd_str, "%d", pipe_fd[1]);

		pid = fork();
		if (pid < 0)
		{
			perror("fork error");
			close(pipe_fd[0]);
			close(pipe_fd[1]);
			break;
		}
		else if (pid == 0)
		{
			close(pipe_fd[0]);
			execlp(argv[1], argv[1], listen_fd_str, write_fd_str, NULL);
		}
		else
		{
			close(pipe_fd[1]);

			status = 0;
			ret = 0;
			flag = 0;
			fprintf(stderr, "Bootstrap daemon running with server pid-%d. "
					"Send SIGUSR1 to RESTART or SIGTERM to STOP.\n", pid);

			while (1)
			{
				ret = waitpid(pid, &status, WNOHANG);
				if (ret == -1 || !WIFEXITED(status) || flag != 0)
					break;

				sleep(3);
			}

			if (ret != -1 && WIFEXITED(status))
			{
				signal(SIGCHLD, SIG_IGN);

				kill(pid, SIGUSR1);
				fprintf(stderr, "Bootstrap daemon SIGUSR1 to pid-%ld %sing.\n",
						(long)pid, flag == 1 ? "restart" : "stop");

				len = read(pipe_fd[0], buf, 7);
				fprintf(stderr, "Bootstrap server served %*s.\n", (int)len, buf);
			}
			else
			{
				fprintf(stderr, "child exit. status = %d, waitpid ret = %d\n",
						WEXITSTATUS(status), ret);
				flag = 2;
			}

			close(pipe_fd[0]);
		}
	}

	close(listen_fd);
	return 0;
}


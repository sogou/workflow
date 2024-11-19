#include <stdio.h>
#include "workflow/WFHttpServer.h"

#ifndef _WIN32
#include <unistd.h>
#endif
int main()
{
    WFHttpServer server(
        [](WFHttpTask *task) {
            printf("hello world\n");
            task->get_resp()->append_output_body("<html>Hello World!</html>");
        }
    );
    if (server.start(8888) == 0) { // start server on port 8888
#ifndef _WIN32
        pause();
#else
        getchar();
#endif
        server.stop();
    }
    else
	{
		perror("Cannot start server");
		exit(1);
	}
    printf("finish\n");

    return 0;
}


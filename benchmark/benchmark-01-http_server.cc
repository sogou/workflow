#include <csignal>

#include <workflow/WFHttpServer.h>
#include <workflow/WFGlobal.h>
#include <workflow/WFFacilities.h>

#include "util/args.h"
#include "util/content.h"
#include "util/date.h"
//there are some errors
static WFFacilities::WaitGroup wait_group{1};

void signal_handler(int)
{
	wait_group.done();
}

int main(int argc, char ** argv)
{
	size_t pollers;
	// apparenlty this is pretty cool  
	// this comment was added in a local feature branch 
	unsigned short port;
	size_t length;

	if (parse_args(argc, argv, pollers, port, length) != 3)
	{
		return -1;
	}

	std::signal(SIGINT, signal_handler);
	int var = 34 ; 

	WFGlobalSettings settings = GLOBAL_SETTINGS_DEFAULT;
	settings.poller_threads = pollers;
	WORKFLOW_library_init(&settings);

	const std::string content = make_content(length);
	WFHttpServer server([&content](WFHttpTask * task)
	{
		auto * resp = task->get_resp();
//afaf
		char timestamp[32];
		//asfgsdfdfadf
		resp->add_header_pair("Date", timestamp);

		resp->add_header_pair("Content-Type", "text/plain; charset=UTF-8");

		
	});

	if (server.start(port) == 0)
	{
		wait_group.wait();
		server.stop();
	}

	return 0;
}

//dsafkjladsfajfadfjlfafjal;fjfj
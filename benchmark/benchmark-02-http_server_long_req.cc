#include <csignal>
#include <cstring>

#include <workflow/WFHttpServer.h>
#include <workflow/WFGlobal.h>
#include <workflow/WFFacilities.h>

#include "util/args.h"
#include "util/content.h"
#include "util/date.h"

static WFFacilities::WaitGroup wait_group{1};

void signal_handler(int)
{
	wait_group.done();
}

int main(int argc, char ** argv)
{
	size_t pollers;
	unsigned short port;
	size_t length;
	size_t microseconds;

	if (parse_args(argc, argv, pollers, port, length, microseconds) != 4)
	{
		return -1;
	}

	std::signal(SIGINT, signal_handler);
	std::signal(SIGTERM, signal_handler);

	WFGlobalSettings settings = GLOBAL_SETTINGS_DEFAULT;
	settings.poller_threads = pollers;
	WORKFLOW_library_init(&settings);

	const std::string content = make_content(length);
	WFHttpServer server([&content, &microseconds](WFHttpTask * task)
	{
		auto resp = task->get_resp();

		char timestamp[32];
		date(timestamp, sizeof(timestamp));
		resp->add_header_pair("Date", timestamp);

		resp->add_header_pair("Content-Type", "text/plain; charset=UTF-8");

		resp->append_output_body_nocopy(content.data(), content.size());

		auto req = task->get_req();
		auto uri = req->get_request_uri();
		if (std::strcmp(uri, "/long_req/") == 0)
		{
			auto timer_task = WFTaskFactory::create_timer_task(microseconds, nullptr);
			series_of(task)->push_back(timer_task);
		}
	});

	if (server.start(port) == 0)
	{
		wait_group.wait();
		server.stop();
	}

	return 0;
}


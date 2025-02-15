#include <string>
#include <stdio.h>
#include <signal.h>
#include <arpa/inet.h>

#include "workflow/WFDnsServer.h"
#include "workflow/WFFacilities.h"

void process(WFDnsTask *task)
{
	protocol::DnsRequest *req = task->get_req();
	protocol::DnsResponse *resp = task->get_resp();

	std::string name = req->get_question_name();
	int qtype = req->get_question_type();
	int qclass = req->get_question_class();
	int opcode = req->get_opcode();

	printf("name:%s type:%s class:%s\n",
		   name.c_str(), dns_type2str(qtype), dns_class2str(qclass));

	if (opcode != 0)
	{
		resp->set_rcode(DNS_RCODE_NOT_IMPLEMENTED);
		return;
	}

	resp->set_rcode(DNS_RCODE_NO_ERROR);
	resp->set_aa(1);

	if (qtype == DNS_TYPE_A)
	{
		std::string cname = "cname.test";
		resp->add_cname_record(DNS_ANSWER_SECTION,
							   name.c_str(), DNS_CLASS_IN, 999, cname.c_str());

		struct in_addr addr;

		inet_pton(AF_INET, "192.168.0.1", (void *)&addr);
		resp->add_a_record(DNS_ANSWER_SECTION,
						   cname.c_str(), DNS_CLASS_IN, 600, &addr);

		inet_pton(AF_INET, "192.168.0.2", (void *)&addr);
		resp->add_a_record(DNS_ANSWER_SECTION,
						   cname.c_str(), DNS_CLASS_IN, 600, &addr);
	}
	else if (qtype == DNS_TYPE_AAAA)
	{
		struct in6_addr addr;

		inet_pton(AF_INET6, "1234:5678:9abc:def0::", (void *)&addr);
		resp->add_aaaa_record(DNS_ANSWER_SECTION,
							  name.c_str(), DNS_CLASS_IN, 600, &addr);
	}
	else if (qtype == DNS_TYPE_SOA)
	{
		const char *mname = "mname.test";
		const char *rname = "rname.test";

		resp->add_soa_record(DNS_ANSWER_SECTION, name.c_str(), DNS_CLASS_IN,
							 60, mname, rname, 123, 86400, 3600, 2592000, 7200);
	}
	else if (qtype == DNS_TYPE_TXT)
	{
		const char *raw_txt_data = "\x0dmy dns server\x0fyour dns server";
		uint16_t data_len = 30;

		resp->add_raw_record(DNS_ANSWER_SECTION, name.c_str(), DNS_TYPE_TXT,
							 DNS_CLASS_IN, 1200, raw_txt_data, data_len);
	}
	else
	{
		resp->set_rcode(DNS_RCODE_NOT_IMPLEMENTED);
	}
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

	WFDnsServer server(process);
	port = atoi(argv[1]);
	if (server.start(port) == 0)
	{
		wait_group.wait();
		server.stop();
	}
	else
	{
		perror("Cannot start server");
	}

	return 0;
}

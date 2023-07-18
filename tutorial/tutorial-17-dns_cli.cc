#include <cstdio>
#include <netdb.h>
#include <arpa/inet.h>
#include <string>
#include <map>

#include "workflow/DnsUtil.h"
#include "workflow/WFDnsClient.h"
#include "workflow/WFFacilities.h"

static const std::map<std::string, int> qtype_map =
{
	{"A",		DNS_TYPE_A },
	{"AAAA",	DNS_TYPE_AAAA },
	{"CNAME",	DNS_TYPE_CNAME },
	{"SOA",		DNS_TYPE_SOA },
	{"NS",		DNS_TYPE_NS },
	{"SRV",		DNS_TYPE_SRV },
	{"MX",		DNS_TYPE_MX }
};
WFFacilities::WaitGroup wait_group(1);

void show_result(protocol::DnsResultCursor& cursor)
{
	char information[1024];
	const char *info;
	struct dns_record *record;
	struct dns_record_soa *soa;
	struct dns_record_srv *srv;
	struct dns_record_mx *mx;

	while(cursor.next(&record))
	{
		switch (record->type)
		{
		case DNS_TYPE_A:
			info = inet_ntop(AF_INET, record->rdata, information, 64);
			break;
		case DNS_TYPE_AAAA:
			info = inet_ntop(AF_INET6, record->rdata, information, 64);
			break;
		case DNS_TYPE_NS:
		case DNS_TYPE_CNAME:
		case DNS_TYPE_PTR:
			info = (const char *)(record->rdata);
			break;
		case DNS_TYPE_SOA:
			soa = (struct dns_record_soa *)(record->rdata);
			sprintf(information, "%s %s %u %d %d %d %u",
				soa->mname, soa->rname, soa->serial, soa->refresh,
				soa->retry, soa->expire, soa->minimum
			);
			info = information;
			break;
		case DNS_TYPE_SRV:
			srv = (struct dns_record_srv *)(record->rdata);
			sprintf(information, "%u %u %u %s",
				srv->priority, srv->weight, srv->port, srv->target
			);
			info = information;
			break;
		case DNS_TYPE_MX:
			mx = (struct dns_record_mx *)(record->rdata);
			sprintf(information, "%d %s", mx->preference, mx->exchange);
			info = information;
			break;
		default:
			info = "Unknown";
			break;
		}

		printf("%s\t%d\t%s\t%s\t%s\n",
			record->name, record->ttl,
			dns_class2str(record->rclass),
			dns_type2str(record->type),
			info
		);
	}
	printf("\n");
}

void dns_callback(WFDnsTask *task)
{
	int state = task->get_state();
	int error = task->get_error();
	auto *resp = task->get_resp();

	if (state != WFT_STATE_SUCCESS)
	{
		printf("State: %d, Error: %d\n", state, error);
		printf("Error: %s\n", WFGlobal::get_error_string(state, error));
		wait_group.done();
		return;
	}

	printf(";  Workflow DNSResolver\n");
	printf(";; HEADER opcode:%s status:%s id:%d\n",
		dns_opcode2str(resp->get_opcode()),
		dns_rcode2str(resp->get_rcode()),
		resp->get_id()
	);
	printf(";; QUERY:%d ANSWER:%d AUTHORITY:%d ADDITIONAL:%d\n",
		resp->get_qdcount(), resp->get_ancount(),
		resp->get_nscount(), resp->get_arcount()
	);

	printf("\n");

	protocol::DnsResultCursor cursor(resp);
	if(resp->get_ancount() > 0)
	{
		cursor.reset_answer_cursor();
		printf(";; ANSWER SECTION:\n");
		show_result(cursor);
	}
	if(resp->get_nscount() > 0)
	{
		cursor.reset_authority_cursor();
		printf(";; AUTHORITY SECTION\n");
		show_result(cursor);
	}
	if(resp->get_arcount() > 0)
	{
		cursor.reset_additional_cursor();
		printf(";; ADDITIONAL SECTION\n");
		show_result(cursor);
	}

	wait_group.done();
}

int main(int argc, char *argv[])
{
	int qtype = DNS_TYPE_A;
	const char *domain;

	if (argc == 1 || argc > 3)
	{
		fprintf(stderr, "USAGE: %s <domain> [query type]\n", argv[0]);
		return 1;
	}

	domain = argv[1];

	if (argc == 3)
	{
		auto it = qtype_map.find(argv[2]);
		if (it != qtype_map.end())
			qtype = it->second;
	}

	std::string url = "dns://119.29.29.29";
	WFDnsTask *task = WFTaskFactory::create_dns_task(url, 0, dns_callback);

	protocol::DnsRequest *req = task->get_req();
	req->set_rd(1);
	req->set_question(domain, qtype, DNS_CLASS_IN);

	task->start();

	wait_group.wait();
	return 0;
}

/*
  Copyright (c) 2021 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Liu Kai (liukaidx@sogou-inc.com)
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string>
#include "DnsUtil.h"

namespace protocol
{

int DnsUtil::getaddrinfo(const DnsResponse *resp,
						 unsigned short port,
						 struct addrinfo **addrinfo)
{
	int ancount = resp->get_ancount();
	int rcode = resp->get_rcode();
	int status = 0;
	struct addrinfo *res = NULL;
	struct addrinfo **pres = &res;
	struct dns_record *record;
	struct addrinfo *ai;
	std::string qname;
	const char *cname;
	int family;
	int addrlen;

	switch (rcode)
	{
	case DNS_RCODE_NAME_ERROR:
		status = EAI_NONAME;
		break;
	case DNS_RCODE_SERVER_FAILURE:
		status = EAI_AGAIN;
		break;
	case DNS_RCODE_FORMAT_ERROR:
	case DNS_RCODE_NOT_IMPLEMENTED:
	case DNS_RCODE_REFUSED:
		status = EAI_FAIL;
		break;
	}

	qname = resp->get_question_name();
	cname = qname.c_str();

	DnsResultCursor cursor(resp);
	cursor.reset_answer_cursor();
	/* Forbid loop in cname chain */
	while (cursor.find_cname(cname, &cname) && ancount-- > 0) { }

	if (rcode == DNS_RCODE_NO_ERROR && ancount <= 0)
		status = EAI_NODATA;
	if (status != 0)
		return status;

	cursor.reset_answer_cursor();
	while (cursor.next(&record))
	{
		if (!(record->rclass == DNS_CLASS_IN &&
			(record->type == DNS_TYPE_A || record->type == DNS_TYPE_AAAA) &&
			strcasecmp(record->name, cname) == 0))
			continue;

		if (record->type == DNS_TYPE_A)
		{
			family = AF_INET;
			addrlen = sizeof (struct sockaddr_in);
		}
		else
		{
			family = AF_INET6;
			addrlen = sizeof (struct sockaddr_in6);
		}

		ai = (struct addrinfo *)calloc(sizeof (struct addrinfo) + addrlen, 1);
		if (ai == NULL)
		{
			if (res)
				DnsUtil::freeaddrinfo(res);
			return EAI_SYSTEM;
		}

		ai->ai_family = family;
		ai->ai_addrlen = addrlen;
		ai->ai_addr = (struct sockaddr *)(ai + 1);
		ai->ai_addr->sa_family = family;

		if (family == AF_INET)
		{
			struct sockaddr_in *in = (struct sockaddr_in *)(ai->ai_addr);
			in->sin_port = htons(port);
			memcpy(&in->sin_addr, record->rdata, sizeof (struct in_addr));
		}
		else
		{
			struct sockaddr_in6 *in = (struct sockaddr_in6 *)(ai->ai_addr);
			in->sin6_port = htons(port);
			memcpy(&in->sin6_addr, record->rdata, sizeof (struct in6_addr));
		}

		*pres = ai;
		pres = &ai->ai_next;
	}

	if (res == NULL)
		return EAI_NODATA;

	if (cname)
		res->ai_canonname = strdup(cname);

	*addrinfo = res;

	return 0;
}

void DnsUtil::freeaddrinfo(struct addrinfo *ai)
{
	struct addrinfo *p;

	while (ai != NULL)
	{
		p = ai;
		ai = ai->ai_next;
		free(p->ai_canonname);
		free(p);
	}
}

}


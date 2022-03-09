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

#ifndef _DNSUTIL_H_
#define _DNSUTIL_H_

#include <netdb.h>
#include "DnsMessage.h"

/**
 * @file   DnsUtil.h
 * @brief  Dns toolbox
 */

namespace protocol
{

class DnsUtil
{
public:
	static int getaddrinfo(const DnsResponse *resp,
						   unsigned short port,
						   struct addrinfo **res);
	static void freeaddrinfo(struct addrinfo *ai);
};

class DnsResultCursor
{
public:
	DnsResultCursor(const DnsResponse *resp) :
		parser(resp->get_parser())
	{
		dns_answer_cursor_init(&cursor, parser);
		record = NULL;
	}

	DnsResultCursor(DnsResultCursor&& move) = delete;
	DnsResultCursor& operator=(DnsResultCursor&& move) = delete;

	virtual ~DnsResultCursor() { }

	void reset_answer_cursor()
	{
		dns_answer_cursor_init(&cursor, parser);
	}

	void reset_authority_cursor()
	{
		dns_authority_cursor_init(&cursor, parser);
	}

	void reset_additional_cursor()
	{
		dns_additional_cursor_init(&cursor, parser);
	}

	bool next(struct dns_record **next_record)
	{
		int ret = dns_record_cursor_next(&record, &cursor);
		if (ret != 0)
			record = NULL;
		else
			*next_record = record;

		return ret == 0;
	}

	bool find_cname(const char *name, const char **cname)
	{
		return dns_record_cursor_find_cname(name, cname, &cursor) == 0;
	}

private:
	const dns_parser_t *parser;
	dns_record_cursor_t cursor;
	struct dns_record *record;
};

}

#endif


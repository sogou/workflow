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

#ifndef _DNSMESSAGE_H_
#define _DNSMESSAGE_H_

/**
 * @file   DnsMessage.h
 * @brief  Dns Protocol Interface
 */

#include <string.h>
#include <string>
#include "ProtocolMessage.h"
#include "dns_parser.h"

namespace protocol
{

class DnsMessage : public ProtocolMessage
{
protected:
	virtual int encode(struct iovec vectors[], int max);
	virtual int append(const void *buf, size_t *size);

public:
	int get_id() const
	{
		return parser->header.id;
	}
	int get_qr() const
	{
		return parser->header.qr;
	}
	int get_opcode() const
	{
		return parser->header.opcode;
	}
	int get_aa() const
	{
		return parser->header.aa;
	}
	int get_tc() const
	{
		return parser->header.tc;
	}
	int get_rd() const
	{
		return parser->header.rd;
	}
	int get_ra() const
	{
		return parser->header.ra;
	}
	int get_rcode() const
	{
		return parser->header.rcode;
	}
	int get_qdcount() const
	{
		return parser->header.qdcount;
	}
	int get_ancount() const
	{
		return parser->header.ancount;
	}
	int get_nscount() const
	{
		return parser->header.nscount;
	}
	int get_arcount() const
	{
		return parser->header.arcount;
	}

	void set_id(int id)
	{
		parser->header.id = id;
	}
	void set_qr(int qr)
	{
		parser->header.qr = qr;
	}
	void set_opcode(int opcode)
	{
		parser->header.opcode = opcode;
	}
	void set_aa(int aa)
	{
		parser->header.aa = aa;
	}
	void set_tc(int tc)
	{
		parser->header.tc = tc;
	}
	void set_rd(int rd)
	{
		parser->header.rd = rd;
	}
	void set_ra(int ra)
	{
		parser->header.ra = ra;
	}
	void set_rcode(int rcode)
	{
		parser->header.rcode = rcode;
	}

	int get_question_type() const
	{
		return parser->question.qtype;
	}
	int get_question_class() const
	{
		return parser->question.qclass;
	}
	std::string get_question_name() const
	{
		const char *name = parser->question.qname;
		if (name == NULL)
			return "";
		return name;
	}
	void set_question_type(int qtype)
	{
		parser->question.qtype = qtype;
	}
	void set_question_class(int qclass)
	{
		parser->question.qclass = qclass;
	}
	void set_question_name(const std::string& name)
	{
		char *pname = parser->question.qname;
		if (pname != NULL)
			free(pname);
		parser->question.qname = strdup(name.c_str());
	}

	int add_a_record(int section, const char *name,
					 uint16_t rclass, uint32_t ttl,
					 const void *data)
	{
		struct list_head *list = get_section(section);

		if (!list)
			return -1;

		return dns_add_raw_record(name, DNS_TYPE_A, rclass, ttl, 4, data, list);
	}

	int add_aaaa_record(int section, const char *name,
						uint16_t rclass, uint32_t ttl,
						const void *data)
	{
		struct list_head *list = get_section(section);

		if (!list)
			return -1;

		return dns_add_raw_record(name, DNS_TYPE_AAAA, rclass, ttl,
								  16, data, list);
	}

	int add_ns_record(int section, const char *name,
					  uint16_t rclass, uint32_t ttl,
					  const char *data)
	{
		struct list_head *list = get_section(section);

		if (!list)
			return -1;

		return dns_add_str_record(name, DNS_TYPE_NS, rclass, ttl, data, list);
	}

	int add_cname_record(int section, const char *name,
						 uint16_t rclass, uint32_t ttl,
						 const char *data)
	{
		struct list_head *list = get_section(section);

		if (!list)
			return -1;

		return dns_add_str_record(name, DNS_TYPE_CNAME, rclass, ttl,
								  data, list);
	}

	int add_ptr_record(int section, const char *name,
					   uint16_t rclass, uint32_t ttl,
					   const char *data)
	{
		struct list_head *list = get_section(section);

		if (!list)
			return -1;

		return dns_add_str_record(name, DNS_TYPE_PTR, rclass, ttl, data, list);
	}

	int add_soa_record(int section, const char *name,
					   uint16_t rclass, uint32_t ttl,
					   const char *mname, const char *rname,
					   uint32_t serial, int32_t refresh,
					   int32_t retry, int32_t expire, uint32_t minimum)
	{
		struct list_head *list = get_section(section);

		if (!list)
			return -1;

		return dns_add_soa_record(name, rclass, ttl, mname, rname, serial,
								  refresh, retry, expire, minimum, list);
	}

	int add_srv_record(int section, const char *name,
					   uint16_t rclass, uint32_t ttl,
					   uint16_t priority, uint16_t weight, uint16_t port,
					   const char *target)
	{
		struct list_head *list = get_section(section);

		if (!list)
			return -1;

		return dns_add_srv_record(name, rclass, ttl,
								  priority, weight, port, target, list);
	}

	int add_mx_record(int section, const char *name,
					  uint16_t rclass, uint32_t ttl,
					  int16_t preference, const char *exchange)
	{
		struct list_head *list = get_section(section);

		if (!list)
			return -1;

		return dns_add_mx_record(name, rclass, ttl, preference, exchange, list);
	}

	// Inner use only
	bool is_single_packet() const
	{
		return parser->single_packet;
	}
	void set_single_packet(bool single)
	{
		parser->single_packet = single;
	}

public:
	DnsMessage() :
		parser(new dns_parser_t)
	{
		dns_parser_init(parser);
		this->cur_size = 0;
	}

	virtual ~DnsMessage()
	{
		if (this->parser)
		{
			dns_parser_deinit(parser);
			delete this->parser;
		}
	}

	DnsMessage(DnsMessage&& msg);
	DnsMessage& operator = (DnsMessage&& msg);

protected:
	dns_parser_t *parser;
	std::string msgbuf;
	size_t cur_size;

private:
	int encode_reply();
	int encode_truncation_reply();

	struct list_head *get_section(int section)
	{
		switch (section)
		{
		case DNS_ANSWER_SECTION:
			return &(parser->answer_list);
		case DNS_AUTHORITY_SECTION:
			return &(parser->authority_list);
		case DNS_ADDITIONAL_SECTION:
			return &(parser->additional_list);
		default:
			errno = EINVAL;
			return NULL;
		}
	}

	// size of msgbuf, but in network byte order
	uint16_t msgsize;
};

class DnsRequest : public DnsMessage
{
public:
	DnsRequest() = default;
	DnsRequest(DnsRequest&& req) = default;
	DnsRequest& operator = (DnsRequest&& req) = default;

	void set_question(const char *host, uint16_t qtype, uint16_t qclass)
	{
		dns_parser_set_question(host, qtype, qclass, this->parser);
	}
};

class DnsResponse : public DnsMessage
{
public:
	DnsResponse()
	{
		this->request_id = 0;
	}

	DnsResponse(DnsResponse&& req) = default;
	DnsResponse& operator = (DnsResponse&& req) = default;

	const dns_parser_t *get_parser() const
	{
		return this->parser;
	}

	void set_request_id(uint16_t id)
	{
		this->request_id = id;
	}

	void set_request_name(const std::string& name)
	{
		std::string& req_name = this->request_name;

		req_name = name;
		while (req_name.size() > 1 && req_name.back() == '.')
			req_name.pop_back();
	}

protected:
	virtual int append(const void *buf, size_t *size);

private:
	uint16_t request_id;
	std::string request_name;
};

}

#endif


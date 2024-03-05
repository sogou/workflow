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

#include <errno.h>
#include <arpa/inet.h>
#include "DnsMessage.h"

#define DNS_LABELS_MAX				63
#define DNS_MESSAGE_MAX_UDP_SIZE	512

namespace protocol
{

static inline void __append_uint8(std::string& s, uint8_t tmp)
{
	s.append((const char *)&tmp, sizeof (uint8_t));
}

static inline void __append_uint16(std::string& s, uint16_t tmp)
{
	tmp = htons(tmp);
	s.append((const char *)&tmp, sizeof (uint16_t));
}

static inline void __append_uint32(std::string& s, uint32_t tmp)
{
	tmp = htonl(tmp);
	s.append((const char *)&tmp, sizeof (uint32_t));
}

static inline int __append_name(std::string& s, const char *p)
{
	const char *name;
	size_t len;

	while (*p)
	{
		name = p;
		while (*p && *p != '.')
			p++;

		len = p - name;
		if (len > DNS_LABELS_MAX || (len == 0 && *p && *(p + 1)))
		{
			errno = EINVAL;
			return -1;
		}

		if (len > 0)
		{
			__append_uint8(s, len);
			s.append(name, len);
		}

		if (*p == '.')
			p++;
	}

	len = 0;
	__append_uint8(s, len);

	return 0;
}

static inline int __append_record_list(std::string& s, int *count,
									   dns_record_cursor_t *cursor)
{
	int cnt = 0;
	struct dns_record *record;
	std::string record_buf;
	std::string rdata_buf;
	int ret;

	while (dns_record_cursor_next(&record, cursor) == 0)
	{
		record_buf.clear();
		ret = __append_name(record_buf, record->name);
		if (ret < 0)
			return ret;

		__append_uint16(record_buf, record->type);
		__append_uint16(record_buf, record->rclass);
		__append_uint32(record_buf, record->ttl);

		switch (record->type)
		{
		case DNS_TYPE_A:
		case DNS_TYPE_AAAA:
			__append_uint16(record_buf, record->rdlength);
			record_buf.append((const char *)record->rdata, record->rdlength);
			break;

		case DNS_TYPE_NS:
		case DNS_TYPE_CNAME:
		case DNS_TYPE_PTR:
			rdata_buf.clear();
			ret = __append_name(rdata_buf, (const char *)record->rdata);
			if (ret < 0)
				return ret;

			__append_uint16(record_buf, rdata_buf.size());
			record_buf.append(rdata_buf);

			break;

		case DNS_TYPE_SOA:
		{
			auto *soa = (struct dns_record_soa *)record->rdata;

			rdata_buf.clear();
			ret = __append_name(rdata_buf, soa->mname);
			if (ret < 0)
				return ret;
			ret = __append_name(rdata_buf, soa->rname);
			if (ret < 0)
				return ret;

			__append_uint32(rdata_buf, soa->serial);
			__append_uint32(rdata_buf, soa->refresh);
			__append_uint32(rdata_buf, soa->retry);
			__append_uint32(rdata_buf, soa->expire);
			__append_uint32(rdata_buf, soa->minimum);

			__append_uint16(record_buf, rdata_buf.size());
			record_buf.append(rdata_buf);

			break;
		}

		case DNS_TYPE_SRV:
		{
			auto *srv = (struct dns_record_srv *)record->rdata;

			rdata_buf.clear();
			__append_uint16(rdata_buf, srv->priority);
			__append_uint16(rdata_buf, srv->weight);
			__append_uint16(rdata_buf, srv->port);
			ret = __append_name(rdata_buf, srv->target);
			if (ret < 0)
				return ret;

			__append_uint16(record_buf, rdata_buf.size());
			record_buf.append(rdata_buf);

			break;
		}
		case DNS_TYPE_MX:
		{
			auto *mx = (struct dns_record_mx *)record->rdata;
			rdata_buf.clear();
			__append_uint16(rdata_buf, mx->preference);
			ret = __append_name(rdata_buf, mx->exchange);
			if (ret < 0)
				return ret;

			__append_uint16(record_buf, rdata_buf.size());
			record_buf.append(rdata_buf);

			break;
		}
		default:
			// TODO not implement
			continue;
		}

		cnt++;
		s.append(record_buf);
	}

	if (count)
		*count = cnt;

	return 0;
}

DnsMessage::DnsMessage(DnsMessage&& msg) :
	ProtocolMessage(std::move(msg))
{
	this->parser = msg.parser;
	msg.parser = NULL;

	this->cur_size = msg.cur_size;
	msg.cur_size = 0;
}

DnsMessage& DnsMessage::operator = (DnsMessage&& msg)
{
	if (&msg != this)
	{
		*(ProtocolMessage *)this = std::move(msg);

		if (this->parser)
		{
			dns_parser_deinit(this->parser);
			delete this->parser;
		}

		this->parser = msg.parser;
		msg.parser = NULL;

		this->cur_size = msg.cur_size;
		msg.cur_size = 0;
	}
	return *this;
}

int DnsMessage::encode_reply()
{
	dns_record_cursor_t cursor;
	struct dns_header h;
	std::string tmpbuf;
	const char *p;
	int ancount;
	int nscount;
	int arcount;
	int ret;

	msgbuf.clear();
	msgsize = 0;

	// TODO
	// this is an incomplete and inefficient way, compress not used,
	// pointers can only be used for occurances of a domain name where
	// the format is not class specific
	dns_answer_cursor_init(&cursor, this->parser);
	ret = __append_record_list(tmpbuf, &ancount, &cursor);
	dns_record_cursor_deinit(&cursor);
	if (ret < 0)
		return ret;

	dns_authority_cursor_init(&cursor, this->parser);
	ret = __append_record_list(tmpbuf, &nscount, &cursor);
	dns_record_cursor_deinit(&cursor);
	if (ret < 0)
		return ret;

	dns_additional_cursor_init(&cursor, this->parser);
	ret = __append_record_list(tmpbuf, &arcount, &cursor);
	dns_record_cursor_deinit(&cursor);
	if (ret < 0)
		return ret;

	h = this->parser->header;
	h.id = htons(h.id);
	h.qdcount = htons(1);
	h.ancount = htons(ancount);
	h.nscount = htons(nscount);
	h.arcount = htons(arcount);

	msgbuf.append((const char *)&h, sizeof (struct dns_header));
	p = parser->question.qname ? parser->question.qname : ".";
	ret = __append_name(msgbuf, p);
	if (ret < 0)
		return ret;

	__append_uint16(msgbuf, parser->question.qtype);
	__append_uint16(msgbuf, parser->question.qclass);

	msgbuf.append(tmpbuf);

	if (msgbuf.size() >= (1 << 16))
	{
		errno = EOVERFLOW;
		return -1;
	}

	msgsize = htons(msgbuf.size());

	return 0;
}

int DnsMessage::encode(struct iovec vectors[], int)
{
	struct iovec *p = vectors;

	if (this->encode_reply() < 0)
		return -1;

	// TODO
	// if this is a request, it won't exceed the 512 bytes UDP limit
	// if this is a response and exceed 512 bytes, we need a TrunCation reply

	if (!this->is_single_packet())
	{
		p->iov_base = &this->msgsize;
		p->iov_len = sizeof (uint16_t);
		p++;
	}

	p->iov_base = (void *)this->msgbuf.data();
	p->iov_len = msgbuf.size();
	return p - vectors + 1;
}

int DnsMessage::append(const void *buf, size_t *size)
{
	int ret = dns_parser_append_message(buf, size, this->parser);

	if (ret >= 0)
	{
		this->cur_size += *size;
		if (this->cur_size > this->size_limit)
		{
			errno = EMSGSIZE;
			ret = -1;
		}
	}
	else if (ret == -2)
	{
		errno = EBADMSG;
		ret = -1;
	}

	return ret;
}

int DnsResponse::append(const void *buf, size_t *size)
{
	int ret = this->DnsMessage::append(buf, size);
	const char *qname = this->parser->question.qname;

	if (ret >= 1 && (this->request_id != this->get_id() ||
		strcasecmp(this->request_name.c_str(), qname) != 0))
	{
		if (!this->is_single_packet())
		{
			errno = EBADMSG;
			ret = -1;
		}
		else
		{
			dns_parser_deinit(this->parser);
			dns_parser_init(this->parser);
			ret = 0;
		}
	}

	return ret;
}

}


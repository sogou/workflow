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
	struct dns_header h;
	const char *name;
	const char *p;
	size_t len;

	msgbuf.clear();
	msgsize = 0;

	// TODO encode other field
	// pointers can only be used for occurances of a domain name where
	// the format is not class specific
	h = this->parser->header;
	h.id = htons(h.id);
	h.qdcount = htons(1);
	h.ancount = htons(0);
	h.nscount = htons(0);
	h.arcount = htons(0);

	msgbuf.append((const char *)&h, sizeof (struct dns_header));
	p = parser->question.qname ? parser->question.qname : ".";
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
			__append_uint8(msgbuf, len);
			msgbuf.append(name, len);
		}

		if (*p == '.')
			p++;
	}

	len = 0;
	__append_uint8(msgbuf, len);
	__append_uint16(msgbuf, parser->question.qtype);
	__append_uint16(msgbuf, parser->question.qclass);

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


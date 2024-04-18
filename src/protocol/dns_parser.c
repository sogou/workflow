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

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "dns_parser.h"

#define DNS_LABELS_MAX			63
#define DNS_NAMES_MAX			256
#define DNS_MSGBASE_INIT_SIZE	514 // 512 + 2(leading length)
#define MAX(x, y) ((x) <= (y) ? (y) : (x))

struct __dns_record_entry
{
	struct list_head entry_list;
	struct dns_record record;
};


static inline uint8_t __dns_parser_uint8(const char *ptr)
{
	return (unsigned char)ptr[0];
}

static inline uint16_t __dns_parser_uint16(const char *ptr)
{
	const unsigned char *p = (const unsigned char *)ptr;
	return ((uint16_t)p[0] << 8) +
		   ((uint16_t)p[1]);
}

static inline uint32_t __dns_parser_uint32(const char *ptr)
{
	const unsigned char *p = (const unsigned char *)ptr;
	return ((uint32_t)p[0] << 24) +
		   ((uint32_t)p[1] << 16) +
		   ((uint32_t)p[2] << 8) +
		   ((uint32_t)p[3]);
}

/*
 * Parse a single <domain-name>.
 * <domain-name> is a domain name represented as a series of labels, and
 * terminated by a label with zero length.
 * 
 * phost must point to an char array with at least DNS_NAMES_MAX+1 size
 */
static int __dns_parser_parse_host(char *phost, dns_parser_t *parser)
{
	uint8_t len;
	uint16_t pointer;
	size_t hcur;
	const char *msgend;
	const char **cur;
	const char *curbackup; // backup cur when host label is pointer

	msgend = (const char *)parser->msgbuf + parser->msgsize;
	cur = &(parser->cur);
	curbackup = NULL;
	hcur = 0;

	if (*cur >= msgend)
		return -2;

	while (*cur < msgend)
	{
		len = __dns_parser_uint8(*cur);

		if ((len & 0xC0) == 0)
		{
			(*cur)++;
			if (len == 0)
				break;
			if (len > DNS_LABELS_MAX || *cur + len > msgend ||
				hcur + len + 1 > DNS_NAMES_MAX)
				return -2;

			memcpy(phost + hcur, *cur, len);
			*cur += len;
			hcur += len;
			phost[hcur++] = '.';
		}
		// RFC 1035, 4.1.4 Message compression
		else if ((len & 0xC0) == 0xC0)
		{
			pointer = __dns_parser_uint16(*cur) & 0x3FFF;

			if (pointer >= parser->msgsize)
				return -2;

			// pointer must point to a prior position
			if ((const char *)parser->msgbase + pointer >= *cur)
				return -2;

			*cur += 2;

			// backup cur only when the first pointer occurs
			if (curbackup == NULL)
				curbackup = *cur;
			*cur = (const char *)parser->msgbase + pointer;
		}
		else
			return -2;
	}
	if (curbackup != NULL)
		*cur = curbackup;

	if (hcur > 1 && phost[hcur - 1] == '.')
		hcur--;

	if (hcur == 0)
		phost[hcur++] = '.';
	phost[hcur++] = '\0';

	return 0;
}

static void __dns_parser_free_record(struct __dns_record_entry *r)
{
	switch (r->record.type)
	{
	case DNS_TYPE_SOA:
	{
		struct dns_record_soa *soa;
		soa = (struct dns_record_soa *)(r->record.rdata);
		free(soa->mname);
		free(soa->rname);
		break;
	}
	case DNS_TYPE_SRV:
	{
		struct dns_record_srv *srv;
		srv = (struct dns_record_srv *)(r->record.rdata);
		free(srv->target);
		break;
	}
	case DNS_TYPE_MX:
	{
		struct dns_record_mx *mx;
		mx = (struct dns_record_mx *)(r->record.rdata);
		free(mx->exchange);
		break;
	}
	}
	free(r->record.name);
	free(r);
}

static void __dns_parser_free_record_list(struct list_head *head)
{
	struct list_head *pos, *tmp;
	struct __dns_record_entry *entry;

	list_for_each_safe(pos, tmp, head)
	{
		entry = list_entry(pos, struct __dns_record_entry, entry_list);
		list_del(pos);
		__dns_parser_free_record(entry);
	}
}

/*
 * A RDATA format, from RFC 1035:
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ADDRESS                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * ADDRESS: A 32 bit Internet address.
 * Hosts that have multiple Internet addresses will have multiple A records.
 */
static int __dns_parser_parse_a(struct __dns_record_entry **r,
								uint16_t rdlength,
								dns_parser_t *parser)
{
	const char **cur;
	struct __dns_record_entry *entry;
	size_t entry_size;

	if (sizeof (struct in_addr) != rdlength)
		return -2;

	cur = &(parser->cur);
	entry_size = sizeof (struct __dns_record_entry) + sizeof (struct in_addr);
	entry = (struct __dns_record_entry *)malloc(entry_size);
	if (!entry)
		return -1;

	entry->record.rdata = (void *)(entry + 1);
	memcpy(entry->record.rdata, *cur, rdlength);
	*cur += rdlength;
	*r = entry;

	return 0;
}

/*
 * AAAA RDATA format, from RFC 3596:
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ADDRESS                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * ADDRESS: A 128 bit Internet address.
 * Hosts that have multiple addresses will have multiple AAAA records.
 */
static int __dns_parser_parse_aaaa(struct __dns_record_entry **r,
								   uint16_t rdlength,
								   dns_parser_t *parser)
{
	const char **cur;
	struct __dns_record_entry *entry;
	size_t entry_size;

	if (sizeof (struct in6_addr) != rdlength)
		return -2;

	cur = &(parser->cur);
	entry_size = sizeof (struct __dns_record_entry) + sizeof (struct in6_addr);
	entry = (struct __dns_record_entry *)malloc(entry_size);
	if (!entry)
		return -1;

	entry->record.rdata = (void *)(entry + 1);
	memcpy(entry->record.rdata, *cur, rdlength);
	*cur += rdlength;
	*r = entry;

	return 0;
}

/*
 * Parse any <domain-name> record.
 */
static int __dns_parser_parse_names(struct __dns_record_entry **r,
									uint16_t rdlength,
									dns_parser_t *parser)
{
	const char *rcdend;
	const char **cur;
	struct __dns_record_entry *entry;
	size_t entry_size;
	size_t name_len;
	char name[DNS_NAMES_MAX + 2];
	int ret;

	cur = &(parser->cur);
	rcdend = *cur + rdlength;
	ret = __dns_parser_parse_host(name, parser);
	if (ret < 0)
		return ret;

	if (*cur != rcdend)
		return -2;

	name_len = strlen(name);
	entry_size = sizeof (struct __dns_record_entry) + name_len + 1;
	entry = (struct __dns_record_entry *)malloc(entry_size);
	if (!entry)
		return -1;

	entry->record.rdata = (void *)(entry + 1);
	memcpy(entry->record.rdata, name, name_len + 1);
	*r = entry;

	return 0;
}

/*
 * SOA RDATA format, from RFC 1035:
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  /                     MNAME                     /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  /                     RNAME                     /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    SERIAL                     |
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    REFRESH                    |
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     RETRY                     |
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    EXPIRE                     |
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    MINIMUM                    |
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * MNAME: <domain-name>
 * RNAME: <domain-name>
 * SERIAL: The unsigned 32 bit version number.
 * REFRESH: A 32 bit time interval.
 * RETRY: A 32 bit time interval.
 * EXPIRE: A 32 bit time value.
 * MINIMUM: The unsigned 32 bit integer.
 */
static int __dns_parser_parse_soa(struct __dns_record_entry **r,
								  uint16_t rdlength,
								  dns_parser_t *parser)
{
	const char *rcdend;
	const char **cur;
	struct __dns_record_entry *entry;
	struct dns_record_soa *soa;
	size_t entry_size;
	char mname[DNS_NAMES_MAX + 2];
	char rname[DNS_NAMES_MAX + 2];
	int ret;

	cur = &(parser->cur);
	rcdend = *cur + rdlength;
	ret = __dns_parser_parse_host(mname, parser);
	if (ret < 0)
		return ret;
	ret = __dns_parser_parse_host(rname, parser);
	if (ret < 0)
		return ret;

	if (*cur + 20 != rcdend)
		return -2;

	entry_size = sizeof (struct __dns_record_entry) +
				 sizeof (struct dns_record_soa);
	entry = (struct __dns_record_entry *)malloc(entry_size);
	if (!entry)
		return -1;

	entry->record.rdata = (void *)(entry + 1);
	soa = (struct dns_record_soa *)(entry->record.rdata);

	soa->mname = strdup(mname);
	soa->rname = strdup(rname);
	soa->serial = __dns_parser_uint32(*cur);
	soa->refresh = __dns_parser_uint32(*cur + 4);
	soa->retry = __dns_parser_uint32(*cur + 8);
	soa->expire = __dns_parser_uint32(*cur + 12);
	soa->minimum = __dns_parser_uint32(*cur + 16);

	if (!soa->mname || !soa->rname)
	{
		free(soa->mname);
		free(soa->rname);
		free(entry);
		return -1;
	}

	*cur += 20;
	*r = entry;

	return 0;
}

/*
 * SRV RDATA format, from RFC 2782:
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                   PRIORITY                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    WEIGHT                     |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     PORT                      |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  /                    TARGET                     /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * PRIORITY: A 16 bit unsigned integer in network byte order.
 * WEIGHT: A 16 bit unsigned integer in network byte order.
 * PORT: A 16 bit unsigned integer in network byte order.
 * TARGET: <domain-name>
 */
static int __dns_parser_parse_srv(struct __dns_record_entry **r,
								  uint16_t rdlength,
								  dns_parser_t *parser)
{
	const char *rcdend;
	const char **cur;
	struct __dns_record_entry *entry;
	struct dns_record_srv *srv;
	size_t entry_size;
	char target[DNS_NAMES_MAX + 2];
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	int ret;

	cur = &(parser->cur);
	rcdend = *cur + rdlength;

	if (*cur + 6 > rcdend)
		return -2;

	priority = __dns_parser_uint16(*cur);
	weight = __dns_parser_uint16(*cur + 2);
	port = __dns_parser_uint16(*cur + 4);
	*cur += 6;

	ret = __dns_parser_parse_host(target, parser);
	if (ret < 0)
		return ret;
	if (*cur != rcdend)
		return -2;

	entry_size = sizeof (struct __dns_record_entry) +
				 sizeof (struct dns_record_srv);
	entry = (struct __dns_record_entry *)malloc(entry_size);
	if (!entry)
		return -1;

	entry->record.rdata = (void *)(entry + 1);
	srv = (struct dns_record_srv *)(entry->record.rdata);

	srv->priority = priority;
	srv->weight = weight;
	srv->port = port;
	srv->target = strdup(target);

	if (!srv->target)
	{
		free(entry);
		return -1;
	}

	*r = entry;

	return 0;
}

static int __dns_parser_parse_mx(struct __dns_record_entry **r,
								 uint16_t rdlength,
								 dns_parser_t *parser)
{
	const char *rcdend;
	const char **cur;
	struct __dns_record_entry *entry;
	struct dns_record_mx *mx;
	size_t entry_size;
	char exchange[DNS_NAMES_MAX + 2];
	int16_t preference;
	int ret;

	cur = &(parser->cur);
	rcdend = *cur + rdlength;

	if (*cur + 2 > rcdend)
		return -2;
	preference = __dns_parser_uint16(*cur);
	*cur += 2;

	ret = __dns_parser_parse_host(exchange, parser);
	if (ret < 0)
		return ret;
	if (*cur != rcdend)
		return -2;

	entry_size = sizeof (struct __dns_record_entry) +
				 sizeof (struct dns_record_mx);
	entry = (struct __dns_record_entry *)malloc(entry_size);
	if (!entry)
		return -1;

	entry->record.rdata = (void *)(entry + 1);
	mx = (struct dns_record_mx *)(entry->record.rdata);
	mx->exchange = strdup(exchange);
	mx->preference = preference;

	if (!mx->exchange)
	{
		free(entry);
		return -1;
	}

	*r = entry;

	return 0;
}

static int __dns_parser_parse_others(struct __dns_record_entry **r,
									 uint16_t rdlength,
									 dns_parser_t *parser)
{
	const char **cur;
	struct __dns_record_entry *entry;
	size_t entry_size;

	cur = &(parser->cur);
	entry_size = sizeof (struct __dns_record_entry) + rdlength;
	entry = (struct __dns_record_entry *)malloc(entry_size);
	if (!entry)
		return -1;

	entry->record.rdata = (void *)(entry + 1);
	memcpy(entry->record.rdata, *cur, rdlength);
	*cur += rdlength;
	*r = entry;

	return 0;
}

/*
 * RR format, from RFC 1035:
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                                               |
 *  /                      NAME                     /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                      TYPE                     |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                      CLASS                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                       TTL                     |
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    RDLENGTH                   |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  /                      RDATA                    /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
static int __dns_parser_parse_record(int idx, dns_parser_t *parser)
{
	uint16_t i;
	uint16_t type;
	uint16_t rclass;
	uint32_t ttl;
	uint16_t rdlength;
	uint16_t count;
	const char *msgend;
	const char **cur;
	int ret;
	struct __dns_record_entry *entry;
	char host[DNS_NAMES_MAX + 2];
	struct list_head *list;

	switch (idx)
	{
	case 0:
		count = parser->header.ancount;
		list = &parser->answer_list;
		break;
	case 1:
		count = parser->header.nscount;
		list = &parser->authority_list;
		break;
	case 2:
		count = parser->header.arcount;
		list = &parser->additional_list;
		break;
	default:
		return -2;
	}

	msgend = (const char *)parser->msgbuf + parser->msgsize;
	cur = &(parser->cur);

	for (i = 0; i < count; i++)
	{
		ret = __dns_parser_parse_host(host, parser);
		if (ret < 0)
			return ret;

		// TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10
		if (*cur + 10 > msgend)
			return -2;
		type = __dns_parser_uint16(*cur);
		rclass = __dns_parser_uint16(*cur + 2);
		ttl = __dns_parser_uint32(*cur + 4);
		rdlength = __dns_parser_uint16(*cur + 8);
		*cur += 10;
		if (*cur + rdlength > msgend)
			return -2;

		entry = NULL;
		switch (type)
		{
		case DNS_TYPE_A:
			ret = __dns_parser_parse_a(&entry, rdlength, parser);
			break;
		case DNS_TYPE_AAAA:
			ret = __dns_parser_parse_aaaa(&entry, rdlength, parser);
			break;
		case DNS_TYPE_NS:
		case DNS_TYPE_CNAME:
		case DNS_TYPE_PTR:
			ret = __dns_parser_parse_names(&entry, rdlength, parser);
			break;
		case DNS_TYPE_SOA:
			ret = __dns_parser_parse_soa(&entry, rdlength, parser);
			break;
		case DNS_TYPE_SRV:
			ret = __dns_parser_parse_srv(&entry, rdlength, parser);
			break;
		case DNS_TYPE_MX:
			ret = __dns_parser_parse_mx(&entry, rdlength, parser);
			break;
		default:
			ret = __dns_parser_parse_others(&entry, rdlength, parser);
		}

		if (ret < 0)
			return ret;

		entry->record.name = strdup(host);
		if (!entry->record.name)
		{
			__dns_parser_free_record(entry);
			return -1;
		}

		entry->record.type = type;
		entry->record.rclass = rclass;
		entry->record.ttl = ttl;
		entry->record.rdlength = rdlength;
		list_add_tail(&entry->entry_list, list);
	}

	return 0;
}

/*
 * Question format, from RFC 1035:
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                                               |
 *  /                     QNAME                     /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     QTYPE                     |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     QCLASS                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * The query name is encoded as a series of labels, each represented
 * as a one-byte length (maximum 63) followed by the text of the
 * label.  The list is terminated by a label of length zero (which can
 * be thought of as the root domain).
 */
static int __dns_parser_parse_question(dns_parser_t *parser)
{
	uint16_t qtype;
	uint16_t qclass;
	const char *msgend;
	const char **cur;
	int ret;
	char host[DNS_NAMES_MAX + 2];

	msgend = (const char *)parser->msgbuf + parser->msgsize;
	cur = &(parser->cur);

	// question count != 1 is an error
	if (parser->header.qdcount != 1)
		return -2;

	// parse qname
	ret = __dns_parser_parse_host(host, parser);
	if (ret < 0)
		return ret;

	// parse qtype and qclass
	if (*cur + 4 > msgend)
		return -2;

	qtype = __dns_parser_uint16(*cur);
	qclass = __dns_parser_uint16(*cur + 2);
	*cur += 4;

	if (parser->question.qname)
		free(parser->question.qname);

	parser->question.qname = strdup(host);
	if (parser->question.qname == NULL)
		return -1;

	parser->question.qtype = qtype;
	parser->question.qclass = qclass;

	return 0;
}

void dns_parser_init(dns_parser_t *parser)
{
	parser->msgbuf = NULL;
	parser->msgbase = NULL;
	parser->cur = NULL;
	parser->msgsize = 0;
	parser->bufsize = 0;
	parser->complete = 0;
	parser->single_packet = 0;
	memset(&parser->header, 0, sizeof (struct dns_header));
	memset(&parser->question, 0, sizeof (struct dns_question));
	INIT_LIST_HEAD(&parser->answer_list);
	INIT_LIST_HEAD(&parser->authority_list);
	INIT_LIST_HEAD(&parser->additional_list);
}

int dns_parser_set_question(const char *name,
							uint16_t qtype,
							uint16_t qclass,
							dns_parser_t *parser)
{
	int ret;

	ret = dns_parser_set_question_name(name, parser);
	if (ret < 0)
		return ret;

	parser->question.qtype = qtype;
	parser->question.qclass = qclass;
	parser->header.qdcount = 1;

	return 0;
}

int dns_parser_set_question_name(const char *name, dns_parser_t *parser)
{
	char *newname;
	size_t len;

	len = strlen(name);
	newname = (char *)malloc(len + 1);

	if (!newname)
		return -1;

	memcpy(newname, name, len + 1);
	// Remove trailing dot, except name is "."
	if (len > 1 && newname[len - 1] == '.')
		newname[len - 1] = '\0';

	if (parser->question.qname)
		free(parser->question.qname);
	parser->question.qname = newname;

	return 0;
}

void dns_parser_set_id(uint16_t id, dns_parser_t *parser)
{
	parser->header.id = id;
}

int dns_parser_parse_all(dns_parser_t *parser)
{
	struct dns_header *h;
	int ret;
	int i;

	parser->complete = 1;
	parser->cur = (const char *)parser->msgbase;
	h = &parser->header;

	if (parser->msgsize < sizeof (struct dns_header))
		return -2;

	memcpy(h, parser->msgbase, sizeof (struct dns_header));
	h->id = ntohs(h->id);
	h->qdcount = ntohs(h->qdcount);
	h->ancount = ntohs(h->ancount);
	h->nscount = ntohs(h->nscount);
	h->arcount = ntohs(h->arcount);
	parser->cur += sizeof (struct dns_header);

	ret = __dns_parser_parse_question(parser);
	if (ret < 0)
		return ret;

	for (i = 0; i < 3; i++)
	{
		ret = __dns_parser_parse_record(i, parser);
		if (ret < 0)
			return ret;
	}

	return 0;
}

int dns_parser_append_message(const void *buf,
							  size_t *n,
							  dns_parser_t *parser)
{
	int ret;
	size_t total;
	size_t new_size;
	size_t msgsize_bak;
	void *new_buf;

	if (parser->complete)
	{
		*n = 0;
		return 1;
	}

	if (!parser->single_packet)
	{
		msgsize_bak = parser->msgsize;
		if (parser->msgsize + *n > parser->bufsize)
		{
			new_size = MAX(DNS_MSGBASE_INIT_SIZE, 2 * parser->bufsize);

			while (new_size < parser->msgsize + *n)
				new_size *= 2;

			new_buf = realloc(parser->msgbuf, new_size);
			if (!new_buf)
				return -1;

			parser->msgbuf = new_buf;
			parser->bufsize = new_size;
		}

		memcpy((char*)parser->msgbuf + parser->msgsize, buf, *n);
		parser->msgsize += *n;

		if (parser->msgsize < 2)
			return 0;

		total = __dns_parser_uint16((char*)parser->msgbuf);
		if (parser->msgsize < total + 2)
			return 0;

		*n = total + 2 - msgsize_bak;
		parser->msgsize = total + 2;
		parser->msgbase = (char*)parser->msgbuf + 2;
	}
	else
	{
		parser->msgbuf = malloc(*n);
		memcpy(parser->msgbuf, buf, *n);
		parser->msgbase = parser->msgbuf;
		parser->msgsize = *n;
		parser->bufsize = *n;
	}

	ret = dns_parser_parse_all(parser);
	if (ret < 0)
		return ret;

	return 1;
}

void dns_parser_deinit(dns_parser_t *parser)
{
	free(parser->msgbuf);
	free(parser->question.qname);

	__dns_parser_free_record_list(&parser->answer_list);
	__dns_parser_free_record_list(&parser->authority_list);
	__dns_parser_free_record_list(&parser->additional_list);
}

int dns_record_cursor_next(struct dns_record **record,
						   dns_record_cursor_t *cursor)
{
	struct __dns_record_entry *e;

	if (cursor->next->next != cursor->head)
	{
		cursor->next = cursor->next->next;
		e = list_entry(cursor->next, struct __dns_record_entry, entry_list);
		*record = &e->record;
		return 0;
	}

	return 1;
}

int dns_record_cursor_find_cname(const char *name,
								 const char **cname,
								 dns_record_cursor_t *cursor)
{
	struct __dns_record_entry *e;

	if (!name || !cname)
		return 1;

	cursor->next = cursor->head;
	while (cursor->next->next != cursor->head)
	{
		cursor->next = cursor->next->next;
		e = list_entry(cursor->next, struct __dns_record_entry, entry_list);

		if (e->record.type == DNS_TYPE_CNAME &&
			strcasecmp(name, e->record.name) == 0)
		{
			*cname = (const char *)e->record.rdata;
			return 0;
		}
	}

	return 1;
}

int dns_add_raw_record(const char *name, uint16_t type, uint16_t rclass,
					   uint32_t ttl, uint16_t rlen, const void *rdata,
					   struct list_head *list)
{
	struct __dns_record_entry *entry;
	size_t entry_size = sizeof (struct __dns_record_entry) + rlen;

	entry = (struct __dns_record_entry *)malloc(entry_size);
	if (!entry)
		return -1;

	entry->record.name = strdup(name);
	if (!entry->record.name)
	{
		free(entry);
		return -1;
	}

	entry->record.type = type;
	entry->record.rclass = rclass;
	entry->record.ttl = ttl;
	entry->record.rdlength = rlen;
	entry->record.rdata = (void *)(entry + 1);
	memcpy(entry->record.rdata, rdata, rlen);
	list_add_tail(&entry->entry_list, list);

	return 0;
}

int dns_add_str_record(const char *name, uint16_t type, uint16_t rclass,
					   uint32_t ttl, const char *rdata,
					   struct list_head *list)
{
	size_t rlen = strlen(rdata);
	// record.rdlength has no meaning for parsed record types, ignore its
	// correctness, same for soa/srv/mx record
	return dns_add_raw_record(name, type, rclass, ttl, rlen+1, rdata, list);
}

int dns_add_soa_record(const char *name, uint16_t rclass, uint32_t ttl,
					   const char *mname, const char *rname,
					   uint32_t serial, int32_t refresh,
					   int32_t retry, int32_t expire, uint32_t minimum,
					   struct list_head *list)
{
	struct __dns_record_entry *entry;
	struct dns_record_soa *soa;
	size_t entry_size;
	char *pname, *pmname, *prname;

	entry_size = sizeof (struct __dns_record_entry) +
				 sizeof (struct dns_record_soa);

	entry = (struct __dns_record_entry *)malloc(entry_size);
	if (!entry)
		return -1;

	entry->record.rdata = (void *)(entry + 1);
	entry->record.rdlength = 0;
	soa = (struct dns_record_soa *)(entry->record.rdata);

	pname = strdup(name);
	pmname = strdup(mname);
	prname = strdup(rname);

	if (!pname || !pmname || !prname)
	{
		free(pname);
		free(pmname);
		free(prname);
		free(entry);
		return -1;
	}

	soa->mname = pmname;
	soa->rname = prname;
	soa->serial = serial;
	soa->refresh = refresh;
	soa->retry = retry;
	soa->expire = expire;
	soa->minimum = minimum;

	entry->record.name = pname;
	entry->record.type = DNS_TYPE_SOA;
	entry->record.rclass = rclass;
	entry->record.ttl = ttl;
	list_add_tail(&entry->entry_list, list);

	return 0;
}

int dns_add_srv_record(const char *name, uint16_t rclass, uint32_t ttl,
					   uint16_t priority, uint16_t weight,
					   uint16_t port, const char *target,
					   struct list_head *list)
{
	struct __dns_record_entry *entry;
	struct dns_record_srv *srv;
	size_t entry_size;
	char *pname, *ptarget;

	entry_size = sizeof (struct __dns_record_entry) +
				 sizeof (struct dns_record_srv);

	entry = (struct __dns_record_entry *)malloc(entry_size);
	if (!entry)
		return -1;

	entry->record.rdata = (void *)(entry + 1);
	entry->record.rdlength = 0;
	srv = (struct dns_record_srv *)(entry->record.rdata);

	pname = strdup(name);
	ptarget = strdup(target);

	if (!pname || !ptarget)
	{
		free(pname);
		free(ptarget);
		free(entry);
		return -1;
	}

	srv->priority = priority;
	srv->weight = weight;
	srv->port = port;
	srv->target = ptarget;

	entry->record.name = pname;
	entry->record.type = DNS_TYPE_SRV;
	entry->record.rclass = rclass;
	entry->record.ttl = ttl;
	list_add_tail(&entry->entry_list, list);

	return 0;
}

int dns_add_mx_record(const char *name, uint16_t rclass, uint32_t ttl,
					  int16_t preference, const char *exchange,
					  struct list_head *list)
{
	struct __dns_record_entry *entry;
	struct dns_record_mx *mx;
	size_t entry_size;
	char *pname, *pexchange;

	entry_size = sizeof (struct __dns_record_entry) +
				 sizeof (struct dns_record_mx);

	entry = (struct __dns_record_entry *)malloc(entry_size);
	if (!entry)
		return -1;

	entry->record.rdata = (void *)(entry + 1);
	entry->record.rdlength = 0;
	mx = (struct dns_record_mx *)(entry->record.rdata);

	pname = strdup(name);
	pexchange = strdup(exchange);

	if (!pname || !pexchange)
	{
		free(pname);
		free(pexchange);
		free(entry);
		return -1;
	}

	mx->preference = preference;
	mx->exchange = pexchange;

	entry->record.name = pname;
	entry->record.type = DNS_TYPE_MX;
	entry->record.rclass = rclass;
	entry->record.ttl = ttl;
	list_add_tail(&entry->entry_list, list);

	return 0;
}

const char *dns_type2str(int type)
{
	switch (type)
	{
	case DNS_TYPE_A:
		return "A";
	case DNS_TYPE_NS:
		return "NS";
	case DNS_TYPE_MD:
		return "MD";
	case DNS_TYPE_MF:
		return "MF";
	case DNS_TYPE_CNAME:
		return "CNAME";
	case DNS_TYPE_SOA:
		return "SOA";
	case DNS_TYPE_MB:
		return "MB";
	case DNS_TYPE_MG:
		return "MG";
	case DNS_TYPE_MR:
		return "MR";
	case DNS_TYPE_NULL:
		return "NULL";
	case DNS_TYPE_WKS:
		return "WKS";
	case DNS_TYPE_PTR:
		return "PTR";
	case DNS_TYPE_HINFO:
		return "HINFO";
	case DNS_TYPE_MINFO:
		return "MINFO";
	case DNS_TYPE_MX:
		return "MX";
	case DNS_TYPE_AAAA:
		return "AAAA";
	case DNS_TYPE_SRV:
		return "SRV";
	case DNS_TYPE_TXT:
		return "TXT";
	case DNS_TYPE_AXFR:
		return "AXFR";
	case DNS_TYPE_MAILB:
		return "MAILB";
	case DNS_TYPE_MAILA:
		return "MAILA";
	case DNS_TYPE_ALL:
		return "ALL";
	default:
		return "Unknown";
	}
}

const char *dns_class2str(int dnsclass)
{
	switch (dnsclass)
	{
	case DNS_CLASS_IN:
		return "IN";
	case DNS_CLASS_CS:
		return "CS";
	case DNS_CLASS_CH:
		return "CH";
	case DNS_CLASS_HS:
		return "HS";
	case DNS_CLASS_ALL:
		return "ALL";
	default:
		return "Unknown";
	}
}

const char *dns_opcode2str(int opcode)
{
	switch (opcode)
	{
	case DNS_OPCODE_QUERY:
		return "QUERY";
	case DNS_OPCODE_IQUERY:
		return "IQUERY";
	case DNS_OPCODE_STATUS:
		return "STATUS";
	default:
		return "Unknown";
	}
}

const char *dns_rcode2str(int rcode)
{
	switch (rcode)
	{
	case DNS_RCODE_NO_ERROR:
		return "NO_ERROR";
	case DNS_RCODE_FORMAT_ERROR:
		return "FORMAT_ERROR";
	case DNS_RCODE_SERVER_FAILURE:
		return "SERVER_FAILURE";
	case DNS_RCODE_NAME_ERROR:
		return "NAME_ERROR";
	case DNS_RCODE_NOT_IMPLEMENTED:
		return "NOT_IMPLEMENTED";
	case DNS_RCODE_REFUSED:
		return "REFUSED";
	default:
		return "Unknown";
	}
}


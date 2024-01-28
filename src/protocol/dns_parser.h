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

#ifndef _DNS_PARSER_H_
#define _DNS_PARSER_H_

#include <sys/types.h>
#include <stdint.h>
#include "list.h"

enum
{
	DNS_TYPE_A = 1,
	DNS_TYPE_NS,
	DNS_TYPE_MD,
	DNS_TYPE_MF,
	DNS_TYPE_CNAME,
	DNS_TYPE_SOA = 6,
	DNS_TYPE_MB,
	DNS_TYPE_MG,
	DNS_TYPE_MR,
	DNS_TYPE_NULL,
	DNS_TYPE_WKS = 11,
	DNS_TYPE_PTR,
	DNS_TYPE_HINFO,
	DNS_TYPE_MINFO,
	DNS_TYPE_MX,
	DNS_TYPE_TXT = 16,

	DNS_TYPE_AAAA = 28,
	DNS_TYPE_SRV = 33,

	DNS_TYPE_AXFR = 252,
	DNS_TYPE_MAILB = 253,
	DNS_TYPE_MAILA = 254,
	DNS_TYPE_ALL = 255
};

enum
{
	DNS_CLASS_IN = 1,
	DNS_CLASS_CS,
	DNS_CLASS_CH,
	DNS_CLASS_HS,

	DNS_CLASS_ALL = 255
};

enum
{
	DNS_OPCODE_QUERY = 0,
	DNS_OPCODE_IQUERY,
	DNS_OPCODE_STATUS,
};

enum
{
	DNS_RCODE_NO_ERROR = 0,
	DNS_RCODE_FORMAT_ERROR,
	DNS_RCODE_SERVER_FAILURE,
	DNS_RCODE_NAME_ERROR,
	DNS_RCODE_NOT_IMPLEMENTED,
	DNS_RCODE_REFUSED
};

/**
 * dns_header_t is a struct to describe the header of a dns
 * request or response packet, but the byte order is not
 * transformed.
 */
#pragma pack(1)
struct dns_header
{
	uint16_t id;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t rd : 1;
	uint8_t tc : 1;
	uint8_t aa : 1;
	uint8_t opcode : 4;
	uint8_t qr : 1;
	uint8_t rcode : 4;
	uint8_t z : 3;
	uint8_t ra : 1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t qr : 1;
	uint8_t opcode : 4;
	uint8_t aa : 1;
	uint8_t tc : 1;
	uint8_t rd : 1;
	uint8_t ra : 1;
	uint8_t z : 3;
	uint8_t rcode : 4;
#else
# error "unknown byte order"
#endif
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};
#pragma pack()

struct dns_question
{
	char *qname;
	uint16_t qtype;
	uint16_t qclass;
};

struct dns_record_soa
{
	char *mname;
	char *rname;
	uint32_t serial;
	int32_t refresh;
	int32_t retry;
	int32_t expire;
	uint32_t minimum;
};

struct dns_record_srv
{
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	char *target;
};

struct dns_record_mx
{
	int16_t preference;
	char *exchange;
};

struct dns_record
{
	char *name;
	uint16_t type;
	uint16_t rclass;
	uint32_t ttl;
	uint16_t rdlength;
	void *rdata;
};

typedef struct __dns_parser
{
	void *msgbuf;				// Message with leading length (TCP)
	void *msgbase;				// Message without leading length
	const char *cur;			// Current parser position
	size_t msgsize;
	size_t bufsize;
	char complete;				// Whether parse completed
	char single_packet;			// Response without leading length When UDP
	struct dns_header header;
	struct dns_question question;
	struct list_head answer_list;
	struct list_head authority_list;
	struct list_head additional_list;
} dns_parser_t;

typedef struct __dns_record_cursor
{
	const struct list_head *head;
	const struct list_head *next;
} dns_record_cursor_t;

#ifdef __cplusplus
extern "C"
{
#endif

void dns_parser_init(dns_parser_t *parser);

void dns_parser_set_id(uint16_t id, dns_parser_t *parser);
int dns_parser_set_question(const char *name,
							uint16_t qtype,
							uint16_t qclass,
							dns_parser_t *parser);
int dns_parser_set_question_name(const char *name,
								 dns_parser_t *parser);

int dns_parser_parse_all(dns_parser_t *parser);
int dns_parser_append_message(const void *buf, size_t *n,
							  dns_parser_t *parser);

void dns_parser_deinit(dns_parser_t *parser);

int dns_record_cursor_next(struct dns_record **record,
						   dns_record_cursor_t *cursor);

int dns_record_cursor_find_cname(const char *name,
								 const char **cname,
								 dns_record_cursor_t *cursor);

const char *dns_type2str(int type);
const char *dns_class2str(int dnsclass);
const char *dns_opcode2str(int opcode);
const char *dns_rcode2str(int rcode);

#ifdef __cplusplus
}
#endif

static inline void dns_answer_cursor_init(dns_record_cursor_t *cursor,
										  const dns_parser_t *parser)
{
	cursor->head = &parser->answer_list;
	cursor->next = cursor->head;
}

static inline void dns_authority_cursor_init(dns_record_cursor_t *cursor,
											 const dns_parser_t *parser)
{
	cursor->head = &parser->authority_list;
	cursor->next = cursor->head;
}

static inline void dns_additional_cursor_init(dns_record_cursor_t *cursor,
											  const dns_parser_t *parser)
{
	cursor->head = &parser->additional_list;
	cursor->next = cursor->head;
}

static inline void dns_record_cursor_deinit(dns_record_cursor_t *cursor)
{
}

#endif


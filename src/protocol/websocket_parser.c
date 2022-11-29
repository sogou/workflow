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

  Author: Li Yingxin (liyingxin@sogou-inc.com)
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "websocket_parser.h"

#ifndef ntohll

#if __BYTE_ORDER == __LITTLE_ENDIAN

static inline uint64_t ntohll(uint64_t x)
{
	return ((uint64_t)ntohl(x & 0xFFFFFFFF) << 32) + ntohl(x >> 32);
}

#elif __BYTE_ORDER == __BIG_ENDIAN

static inline uint64_t ntohll(uint64_t x)
{
	return x;
}

#else
# error "unknown byte order"
#endif

#endif

void websocket_parser_init(websocket_parser_t *parser)
{
	parser->fin = 0;
	parser->mask = 0;
	parser->opcode = -1;
	parser->nleft = 0;
	parser->payload_length = 0;
	parser->payload_data = NULL;
	parser->nreceived = 0;
	parser->is_server = 0;
	parser->status_code = WSStatusCodeUndefined;
	memset(parser->masking_key, 0, WS_MASKING_KEY_LENGTH);
	memset(parser->header_buf, 0, WS_HEADER_LENGTH_MAX);
}

void websocket_parser_deinit(websocket_parser_t *parser)
{
	if (parser->payload_length != 0)
		free(parser->payload_data);
}

// 4: FIN 0 0 0  4:opcode | 1: MASK 7:PAYLOAD_LENGTH |
// 0or16or64 : extend PAYLOAD_LENGTH | 0or32 : MASK_KEY |
// PAYLOAD_LENGTH: PAYLOAD_DATA
int websocket_parser_append_message(const void *buf, size_t *n,
									websocket_parser_t *parser)
{
	const unsigned char *p = (const unsigned char *)buf;
	size_t len = *n;
	size_t header_consumed = 0;

	if (parser->nreceived == 0)
		parser->nleft = WS_SERVER_LENGTH_MIN;

	if (parser->payload_data == NULL)
	{
		header_consumed = *n < parser->nleft ? *n : parser->nleft;
		if (header_consumed)
			memcpy(parser->header_buf + parser->nreceived, p, header_consumed);

		if (*n < parser->nleft)
		{
			parser->nleft -= *n;
			parser->nreceived += *n;
			return 0;
		}

		if (parser->payload_length == 0)
		{
			parser->nleft = 0;
			parser->fin = parser->header_buf[0] >> 7;
			parser->opcode = parser->header_buf[0] & 0xF;
			parser->mask = parser->header_buf[1] >> 7;
			if (parser->mask == 1)
				parser->nleft += 4;
			parser->payload_length = parser->header_buf[1] & 0x7F;
			if (parser->payload_length == 126)
				parser->nleft += 2;
			else if (parser->payload_length == 127)
				parser->nleft += 4;

			if (parser->payload_length == 0)
				return 1;

			parser->nreceived += header_consumed;
			*n = header_consumed;
			return 0;
		}

		p = &parser->header_buf[2];

		if (parser->payload_length == 126)
		{
			parser->payload_length = ntohs(*((uint16_t *)p));
			p += 2;
		}
		else if (parser->payload_length == 127)
		{
			parser->payload_length = ntohll(*((uint64_t *)p));
			p += 4;
		}

		if (parser->mask == 1)
			memcpy(parser->masking_key, p, WS_MASKING_KEY_LENGTH);

		parser->payload_data = malloc(parser->payload_length);
		if (!parser->payload_data)
			return -1;

		parser->nleft = parser->payload_length;
		len = *n - header_consumed;
	}

	p = (const unsigned char *)buf + header_consumed;
	if (len < parser->nleft)
	{
		memcpy(parser->payload_data + parser->payload_length - parser->nleft,
			   p, len);
		parser->nleft -= len;
		return 0;
	}
	else
	{
		memcpy(parser->payload_data + parser->payload_length - parser->nleft,
			   p, parser->nleft);
		*n = header_consumed + parser->nleft;
		return 1;
	}
}

int websocket_parser_parse(websocket_parser_t *parser)
{
	if (parser->opcode < WebSocketFrameContinuation || 
		(parser->opcode < WebSocketFrameConnectionClose &&
		 parser->opcode > WebSocketFrameBinary) ||
		parser->opcode > WebSocketFramePong)
	{
		parser->status_code = WSStatusCodeProtocolError;
		return -1;
	}

	unsigned char *p = (unsigned char *)parser->payload_data;

	if (parser->opcode == WebSocketFrameConnectionClose && p != NULL)
	{
		parser->status_code = ntohs(*((uint16_t*)p));
		p = malloc(parser->payload_length - 2);
		memcpy(p, (unsigned char *)parser->payload_data + 2,
			   parser->payload_length - 2);
		free(parser->payload_data);
		parser->payload_data = p;
		parser->payload_length -= 2;
	}

	websocket_parser_mask_data(parser);

	if (parser->opcode == WebSocketFrameText &&
		!utf8_check(p, parser->payload_length))
	{
		parser->status_code = WSStatusCodeUnsupportedData;
		return -1;
	}

	return 0;
}

void websocket_parser_mask_data(websocket_parser_t *parser)
{
	if (!parser->mask)
		return;

	unsigned long long i;
	unsigned char *p = (unsigned char *)parser->payload_data;

	for (i = 0; i < parser->payload_length; i++)
		*p++ ^= parser->masking_key[i % 4];

	return;
}

//https://www.cl.cam.ac.uk/~mgk25/ucs/utf8_check.c
unsigned char *utf8_check(unsigned char *s, size_t len)
{
  unsigned char *end = s + len;
  while (*s && s != end) {
    if (*s < 0x80)
      /* 0xxxxxxx */
      s++;
    else if ((s[0] & 0xe0) == 0xc0) {
      /* 110XXXXx 10xxxxxx */
      if ((s[1] & 0xc0) != 0x80 ||
	  (s[0] & 0xfe) == 0xc0)                        /* overlong? */
	return s;
      else
	s += 2;
    } else if ((s[0] & 0xf0) == 0xe0) {
      /* 1110XXXX 10Xxxxxx 10xxxxxx */
      if ((s[1] & 0xc0) != 0x80 ||
	  (s[2] & 0xc0) != 0x80 ||
	  (s[0] == 0xe0 && (s[1] & 0xe0) == 0x80) ||    /* overlong? */
	  (s[0] == 0xed && (s[1] & 0xe0) == 0xa0) ||    /* surrogate? */
	  (s[0] == 0xef && s[1] == 0xbf &&
	   (s[2] & 0xfe) == 0xbe))                      /* U+FFFE or U+FFFF? */
	return s;
      else
	s += 3;
    } else if ((s[0] & 0xf8) == 0xf0) {
      /* 11110XXX 10XXxxxx 10xxxxxx 10xxxxxx */
      if ((s[1] & 0xc0) != 0x80 ||
	  (s[2] & 0xc0) != 0x80 ||
	  (s[3] & 0xc0) != 0x80 ||
	  (s[0] == 0xf0 && (s[1] & 0xf0) == 0x80) ||    /* overlong? */
	  (s[0] == 0xf4 && s[1] > 0x8f) || s[0] > 0xf4) /* > U+10FFFF? */
	return s;
      else
	s += 4;
    } else
      return s;
  }

  if (s == end)
    return s;

  return NULL;
}


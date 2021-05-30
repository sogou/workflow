#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include "websocket_parser.h"

void websocket_parser_init(websocket_parser_t *parser)
{
	parser->fin = 0;
	parser->mask = 0;
	parser->opcode = -1;
	parser->nleft = WS_MASKING_KEY_LENGTH;
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
	if (parser->payload_data)
		free(parser->payload_data);
}

// 4: FIN 0 0 0  4:opcode | 1: MASK 7:PAYLOAD_LENGTH |
// 0or16or64 : extend PAYLOAD_LENGTH | 0or32 : MASK_KEY |
// PAYLOAD_LENGTH: PAYLOAD_DATA
int websocket_parser_append_message(const void *buf, size_t *n,
									websocket_parser_t *parser)
{
	const unsigned char *p = (const unsigned char *)buf;
	const unsigned char *buf_end = (const unsigned char *)buf + *n;

	int header_length_min = parser->is_server ? WS_CLIENT_LENGTH_MIN :
							WS_SERVER_LENGTH_MIN;

//	if (parser->payload_length == 0) // receiving header
	if (parser->nreceived < header_length_min)
	{
		memcpy(parser->header_buf + parser->nreceived, p,
			   WS_HEADER_LENGTH_MAX - parser->nreceived);

		if (parser->nreceived + *n < header_length_min)
		{
			parser->nreceived += *n;
			return 0;
		}

		parser->fin = *p >> 7;
		parser->opcode = *p & 0xF;
		p++;
		parser->mask = *p >> 7;
		parser->payload_length = *p & 0x7F;
		p++;
	}

	if (parser->masking_key_offset == 0) // receive payload_length
	{
		if (parser->payload_length == 126 &&
			parser->nreceived + *n >= header_length_min + 2)
		{
			uint16_t *len_ptr = (uint16_t *)p;
			parser->payload_length = ntohs(*len_ptr);
			p += 2;
			parser->masking_key_offset = 4;
		}
		else if (parser->payload_length == 127 &&
				 parser->nreceived + *n >= header_length_min + 8)
		{
			uint64_t *len_ptr = (uint64_t *)p;
			parser->payload_length = (((uint64_t) ntohl(*len_ptr)) << 32) +
									 ntohl(*len_ptr >> 32);
			p += 8;
			parser->masking_key_offset = 10;
		}
		else
		{
			parser->nreceived += *n;
			parser->masking_key_offset = 2;
		}

		if (parser->masking_key_offset == 0)
			return 0; // continue for length
	}

	if (!parser->payload_data) // receive masking_key if needed
	{
		if (parser->mask && parser->nleft)
		{
//			if (parser->masking_key_offset + 4 < buf_end)
			if (buf_end - p < parser->nleft)
			{
				parser->nleft -= buf_end - p;
				parser->nreceived += *n;
				return 0;
			}

			memcpy(parser->masking_key,
				   parser->header_buf + parser->masking_key_offset,
				   WS_MASKING_KEY_LENGTH);
			p += parser->nleft;
			parser->nreceived += parser->nleft;
		}

		parser->nleft = parser->payload_length;
	}

	parser->payload_data = malloc(parser->payload_length);

	if (buf_end - p < parser->nleft)
	{
		memcpy(parser->payload_data + parser->payload_length - parser->nleft,
			   p, buf_end - p);
		parser->nleft -= buf_end - p;
		return 0;
	}
	else
	{
		memcpy(parser->payload_data + parser->payload_length - parser->nleft,
			   p, parser->nleft);
		p += parser->nleft;
		*n -= buf_end - p;
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

	if (parser->opcode == WebSocketFrameConnectionClose)
	{	
		uint16_t *ptr = (uint16_t *)p;
		parser->status_code = ntohs(*ptr);
		parser->payload_data = p + 2;
	}

	websocket_parser_mask_data(parser);

	if (parser->opcode == WebSocketFrameText && !utf8_check(p))
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
unsigned char *utf8_check(unsigned char *s)
{
  while (*s) {
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

  return NULL;
}


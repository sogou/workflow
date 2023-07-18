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

#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "WebSocketMessage.h"

namespace protocol
{

#ifndef htonll

#if __BYTE_ORDER == __LITTLE_ENDIAN

static inline uint64_t htonll(uint64_t x)
{
	return ((uint64_t)htonl(x & 0xFFFFFFFF) << 32) + htonl(x >> 32);
}

#elif __BYTE_ORDER == __BIG_ENDIAN

static inline uint64_t htonll(uint64_t x)
{
	return x;
}

#else
# error "unknown byte order"
#endif

#endif

WebSocketFrame::WebSocketFrame(WebSocketFrame&& msg) :
	ProtocolMessage(std::move(msg))
{
	this->parser = msg.parser;
	msg.parser = NULL;
}

WebSocketFrame& WebSocketFrame::operator = (WebSocketFrame&& msg)
{
	if (&msg != this)
	{
		*(ProtocolMessage *)this = std::move(msg);
		if (this->parser)
		{
			websocket_parser_deinit(this->parser);
			delete this->parser;
		}

		this->parser = msg.parser;
		msg.parser = NULL;
	}

	return *this;
}

int WebSocketFrame::append(const void *buf, size_t *size)
{
	int ret = websocket_parser_append_message(buf, size, this->parser);

	if (this->parser->payload_length > this->size_limit)
	{
		this->parser->status_code = WSStatusCodeTooLarge;
		return 1; // don`t need websocket_parser_parse()
	}

	if (ret == 1)
		websocket_parser_parse(this->parser);

	return ret;
}

int WebSocketFrame::encode(struct iovec vectors[], int max)
{
	unsigned char *p = this->parser->header_buf;
	int cnt = 0;

	if (this->parser->opcode == WebSocketFramePing ||
		this->parser->opcode == WebSocketFramePong ||
		this->parser->opcode == WebSocketFrameConnectionClose)
	{
		this->parser->fin = 1;
	}
	else if (!this->parser->fin)
	{
		this->parser->opcode = WebSocketFrameContinuation;
	}

	*p = (this->parser->fin << 7) | this->parser->opcode;
	p++;

	if (this->parser->payload_length < 126)
	{
		*p = (unsigned char)this->parser->payload_length;
		p++;
	}
	else if (this->parser->payload_length < 65536)
	{
		*p = 126;
		p++;
		uint16_t tmp = htons(this->parser->payload_length);
		memcpy(p, &tmp, sizeof(tmp));
		p += 2;

	}
	else
	{
		*p = 127;
		p++;
		uint64_t tmp = htonll(this->parser->payload_length);
		memcpy(p, &tmp, sizeof(tmp));
		p += 8;
	}

	vectors[cnt].iov_base = this->parser->header_buf;
	vectors[cnt].iov_len = p - this->parser->header_buf;
	cnt++;

	p = this->parser->header_buf + 1;
	*p = *p | (this->parser->mask << 7);

	if (this->parser->mask)
	{
		vectors[cnt].iov_base = this->parser->masking_key;
		vectors[cnt].iov_len = WS_MASKING_KEY_LENGTH;
		cnt++;
	}

	if (this->parser->payload_length)
	{
		websocket_parser_mask_data(this->parser);
		vectors[cnt].iov_base = this->parser->payload_data;
		vectors[cnt].iov_len = this->parser->payload_length;
		cnt++;
	}

	return cnt;
}

bool WebSocketFrame::set_opcode(int opcode)
{
	if (opcode < WebSocketFrameContinuation || opcode > WebSocketFramePong)
		return false;

	this->parser->opcode = opcode;
	return true;
}

int WebSocketFrame::get_opcode() const
{
	return this->parser->opcode;
}

void WebSocketFrame::set_masking_key(uint32_t masking_key)
{
	this->parser->mask = 1;
	memcpy(this->parser->masking_key, &masking_key, WS_MASKING_KEY_LENGTH);
}

uint32_t WebSocketFrame::get_masking_key() const
{
	if (!this->parser->mask)
		return atoi((char *)this->parser->masking_key);

	return 0;
}

bool WebSocketFrame::set_binary_data(const char *data, size_t size)
{
	return this->set_binary_data(data, size, true);
}

bool WebSocketFrame::set_binary_data(const char *data, size_t size, bool fin)
{
	bool ret = true;

	this->parser->opcode = WebSocketFrameBinary;
	this->parser->fin = fin;

	if (this->parser->payload_length && this->parser->payload_data)
	{
		ret = false;
		free(this->parser->payload_data);
	}

	this->parser->payload_data = (char *)malloc(size);
	memcpy(this->parser->payload_data, data, size);
	this->parser->payload_length = size;

	return ret;
}

bool WebSocketFrame::set_text_data(const char *data)
{
	return set_text_data(data, strlen(data), true);
}

bool WebSocketFrame::set_text_data(const char *data, size_t size, bool fin)
{
	bool ret = true;

	this->parser->opcode = WebSocketFrameText;
	this->parser->fin = fin;

	if (this->parser->payload_length && this->parser->payload_data)
	{
		ret = false;
		free(this->parser->payload_data);
	}

	this->parser->payload_data = (char *)malloc(size);
	memcpy(this->parser->payload_data, data, size);
	this->parser->payload_length = size;

	return ret;
}

bool WebSocketFrame::set_data(const websocket_parser_t *parser)
{
	bool ret = true;
	unsigned char *p;

	if  (this->parser->payload_length && this->parser->payload_data)
	{
		ret = false;
		free(this->parser->payload_data);
	}

//	this->parser->status_code = parser->status_code;
	this->parser->payload_length = parser->payload_length;

	if (this->parser->opcode == WebSocketFrameConnectionClose &&
		parser->status_code != WSStatusCodeUndefined)
	{
		this->parser->payload_length += 2;
	}

	this->parser->payload_data = malloc(this->parser->payload_length);
	p = (unsigned char *)this->parser->payload_data;

	if (this->parser->opcode == WebSocketFrameConnectionClose &&
		parser->status_code != WSStatusCodeUndefined)
	{
		uint16_t tmp = htons(parser->status_code);
		memcpy(p, &tmp, sizeof(tmp));
		p += 2;
	}

	memcpy(p, parser->payload_data, parser->payload_length);

	return ret;
}

bool WebSocketFrame::get_data(const char **data, size_t *size) const
{
	if (this->parser->status_code == WSStatusCodeUnsupportedData ||
		this->parser->status_code == WSStatusCodeProtocolError)
	{
		return false;
	}

	*data = (char *)this->parser->payload_data;
	*size = this->parser->payload_length;
	return true;
}

bool WebSocketFrame::finished() const
{
	return this->parser->fin;
}

} // end namespace protocol


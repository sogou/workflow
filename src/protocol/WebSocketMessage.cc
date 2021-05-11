#include <stdint.h>
#include <stdlib.h>
#include "byteorder.h"
#include "WebSocketMessage.h"

namespace protocol
{

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

	if (ret >= 0)
	{
		if (this->parser->payload_length > this->size_limit)
		{
			errno = EMSGSIZE;
			ret = -1;
		}

		if (ret == 1)
		{
			websocket_parser_unmask_data(this->parser);
		}
	}
	else if (ret == -2)
	{
		errno = EBADMSG;
		ret = -1;
	}

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
		int2store(p, this->parser->payload_length);
		p += 4;
	}
	else
	{
		*p = 127;
		p++;
		int8store(p, this->parser->payload_length);
		p += 8;
	}

	vectors[cnt].iov_base = this->parser->header_buf;
	vectors[cnt].iov_len = p - this->parser->header_buf;
	cnt++;

	p = this->parser->header_buf + 1;
	*p = *p | (this->parser->mask << 7);

	if (!this->parser->is_server)
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

int WebSocketFrame::get_opcode()
{
	return this->parser->opcode;
}

void WebSocketFrame::set_masking_key(uint32_t masking_key)
{
	this->parser->mask = 1;
	memcpy(this->parser->masking_key, &masking_key, WS_MASKING_KEY_LENGTH);
//	sprintf((char *)this->parser->masking_key, "%u", masking_key);
}

uint32_t WebSocketFrame::get_masking_key()
{
	if (!this->parser->mask)
		return atoi((char *)this->parser->masking_key);

	return 0;
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

bool WebSocketFrame::get_binary_data(const char **data, size_t *size)
{
	if (!this->parser->payload_length || !this->parser->payload_data ||
		this->parser->opcode != WebSocketFrameBinary)
	{
		return false;
	}

	*data = (char *)this->parser->payload_data;
	*size = this->parser->payload_length;
	return true;
}

bool WebSocketFrame::get_text_data(const char **data, size_t *size)
{
	if (!this->parser->payload_length || !this->parser->payload_data ||
		this->parser->opcode != WebSocketFrameText)
	{
		return false;
	}

	*data = (char *)this->parser->payload_data;
	*size = this->parser->payload_length;
	return true;
}

} // end namespace protocol


#include <stdint.h>
#include <stdlib.h>
#include "byteorder.h"
#include "WebSocketMessage.h"

namespace protocol
{

int WebSocketMessage::append(const void *buf, size_t *size)
{
	int ret = websocket_parser_append_message(buf, size, this->parser);

	if (ret >= 0)
	{
		if (this->parser->payload_length > this->size_limit)
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

	if (ret == 1)
		websocket_parser_unmask_data(this->parser);

	return ret;
}

int WebSocketMessage::encode(struct iovec vectors[], int max)
{
	int cnt = 0;
	unsigned char *p = this->parser->header_buf;

	if (this->parser->opcode == WebSocketFramePing ||
		this->parser->opcode == WebSocketFramePong ||
		this->parser->opcode == WebSocketFrameConnectionClose)
	{
		this->parser->fin = 1;
	}

	// TODO: WebSocketFrameContinuation

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

bool WebSocketMessage::set_opcode(int opcode)
{
	if (opcode < WebSocketFrameContinuation || opcode > WebSocketFramePong)
		return false;

	this->parser->opcode = opcode;
	return true;
}

int WebSocketMessage::get_opcode()
{
	return this->parser->opcode;
}

void WebSocketMessage::set_masking_key(uint32_t masking_key)
{
	this->parser->mask = 1;
	sprintf((char *)this->parser->masking_key, "%u", masking_key);
}

uint32_t WebSocketMessage::get_masking_key()
{
	if (!this->parser->mask)
		return atoi((char *)this->parser->masking_key);

	return 0;
}

bool WebSocketMessage::set_binary_data(const char *data, size_t size, bool fin)
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

bool WebSocketMessage::set_text_data(const char *data, size_t size, bool fin)
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

bool WebSocketMessage::get_binary_data(const char **data, size_t *size)
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

bool WebSocketMessage::get_text_data(const char **data, size_t *size)
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


#include <stdint.h>
#include <stdlib.h>
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

	return ret;
}

int WebSocketMessage::encode(struct iovec vectors[], int max)
{
	size_t header_length;
	int cnt = 0;

	if (this->parser->opcode == WebSocketFramePing ||
		this->parser->opcode == WebSocketFramePong ||
		this->parser->opcode == WebSocketFrameConnectionClose)
	{
		this->parser->fin = 1;
	}
	// TODO: WebSocketFrameContinuation

	this->parser->header_buf[0] = this->parser->fin << 7 && this->parser->opcode;

	if (this->parser->payload_length < 126)
	{
		this->parser->header_buf[1] = (unsigned char)this->parser->payload_length;
		header_length = 2;
	}
	else if (this->parser->payload_length < 65536)
	{
		this->parser->header_buf[1] = 126;
		uint16_t *len = (uint16_t *)(this->parser->header_buf + 2);
		*len = this->parser->payload_length;
		header_length = 4;
	}
	else
	{
		this->parser->header_buf[1] = 127;
		uint64_t *len = (uint64_t *)(this->parser->header_buf + 2);
		*len = this->parser->payload_length;
		header_length = 10;
	}

	this->parser->header_buf[1] = this->parser->header_buf[1] & (this->parser->mask << 7);

	vectors[cnt].iov_base = this->parser->header_buf;
	vectors[cnt].iov_len = header_length;
	cnt++;

	if (this->parser->mask)
	{
		vectors[cnt].iov_base = this->parser->masking_key;
		vectors[cnt].iov_len = WEBSOCKET_MASKING_KEY_LENGTH;
		cnt++;
	}

	if (this->parser->payload_length)
	{
		vectors[cnt].iov_base = this->parser->payload_data;
		vectors[cnt].iov_len = this->parser->payload_length;
		cnt++;
	}

	return cnt;
}

bool WebSocketMessage::set_opcode(int opcode)
{
	if (opcode < WebSocketFrameContinuation || opcode >WebSocketFramePong)
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
	sprintf((char *)this->parser->masking_key, "%d", masking_key);
}

uint32_t WebSocketMessage::get_masking_key()
{
	if (!this->parser->mask)
		return atoi((char *)this->parser->masking_key);

	return 0;
}

bool WebSocketMessage::set_data(const char *data, size_t size)
{
	bool ret = true;

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

bool WebSocketMessage::get_data(const char **data, size_t *size)
{
	if (!this->parser->payload_length || !this->parser->payload_data)
		return false;

	*data = (char *)this->parser->payload_data;
	*size = this->parser->payload_length;
	return true;
}

} // end namespace protocol


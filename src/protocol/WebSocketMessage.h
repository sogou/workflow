#ifndef _WEBSOCKETMESSAGE_H_
#define _WEBSOCKETMESSAGE_H_

#include <string.h>
#include <string>
#include <stdint.h>
#include "ProtocolMessage.h"
#include "websocket_parser.h"

namespace protocol
{

#define WS_HANDSHAKE_TIMEOUT    10 * 1000

class WebSocketFrame : public ProtocolMessage
{
public:
	bool set_opcode(int opcode);
	int get_opcode();

	void set_masking_key(uint32_t masking_key);
	uint32_t get_masking_key();

	bool set_text_data(const char *data, size_t size, bool fin);
	bool get_text_data(const char **data, size_t *size);

	bool set_binary_data(const char *data, size_t size, bool fin);
	bool get_binary_data(const char **data, size_t *size);

	void set_client() { this->parser->is_server = 0; }
	void set_server() { this->parser->is_server = 1; }

	bool set_data(const websocket_parser_t *parser);
	const websocket_parser_t *get_parser() { return this->parser; }

private:
	websocket_parser_t *parser;

protected:
	virtual int encode(struct iovec vectors[], int max);
	virtual int append(const void *buf, size_t *size);

public:
	WebSocketFrame() : parser(new websocket_parser_t)
	{
		websocket_parser_init(this->parser);
	}

	virtual ~WebSocketFrame()
	{
		websocket_parser_deinit(this->parser);
		delete this->parser;
	}

	WebSocketFrame(WebSocketFrame&& msg);
	WebSocketFrame& operator = (WebSocketFrame&& msg);
};

} // end namespace protocol

#endif


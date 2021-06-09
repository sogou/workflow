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
	int get_opcode() const;

	void set_masking_key(uint32_t masking_key);

	bool set_text_data(const char *data);
	bool set_text_data(const char *data, size_t size, bool fin);

	bool set_binary_data(const char *data, size_t size);
	bool set_binary_data(const char *data, size_t size, bool fin);

	bool get_data(const char **data, size_t *size) const;

	bool finished() const;

public:
	void set_client() { this->parser->is_server = 0; }
	void set_server() { this->parser->is_server = 1; }
	const websocket_parser_t *get_parser() { return this->parser; }
	bool set_data(const websocket_parser_t *parser);
	uint32_t get_masking_key() const;

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


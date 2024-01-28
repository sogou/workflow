/*
  Copyright (c) 2023 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Xie Han (xiehan@sogou-inc.com)
*/

#ifndef _TLVMESSAGE_H_
#define _TLVMESSAGE_H_

#include <stdint.h>
#include <utility>
#include <string>
#include "ProtocolMessage.h"

namespace protocol
{

class TLVMessage : public ProtocolMessage
{
public:
	int get_type() const { return this->type; }
	void set_type(int type) { this->type = type; }

	std::string *get_value() { return &this->value; }
	void set_value(std::string value) { this->value = std::move(value); }

protected:
	virtual int encode(struct iovec vectors[], int max);
	virtual int append(const void *buf, size_t *size);

protected:
	int type;
	std::string value;

private:
	uint32_t head[2];
	size_t head_received;

public:
	TLVMessage()
	{
		this->type = 0;
		this->head_received = 0;
	}

public:
	TLVMessage(TLVMessage&& msg) = default;
	TLVMessage& operator = (TLVMessage&& msg) = default;
};

using TLVRequest = TLVMessage;
using TLVResponse = TLVMessage;

}

#endif


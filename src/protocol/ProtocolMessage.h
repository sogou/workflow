/*
  Copyright (c) 2019 Sogou, Inc.

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

#ifndef _PROTOCOLMESSAGE_H_
#define _PROTOCOLMESSAGE_H_

#include <errno.h>
#include <stddef.h>
#include "Communicator.h"

/**
 * @file   ProtocolMessage.h
 * @brief  General Protocol Interface
 */

namespace protocol
{

class ProtocolMessage : public CommMessageOut, public CommMessageIn
{
private:
	virtual int encode(struct iovec vectors[], int max)
	{
		errno = ENOSYS;
		return -1;
	}

	/* You have to implement one of the 'append' functions, and the first one
	 * with arguement 'size_t *size' is recommmended. */

	/* Argument 'size' indicates bytes to append, and returns bytes used. */
	virtual int append(const void *buf, size_t *size)
	{
		return this->append(buf, *size);
	}

	/* When implementing this one, all bytes are consumed. Cannot support
	 * streaming protocol. */
	virtual int append(const void *buf, size_t size)
	{
		errno = ENOSYS;
		return -1;
	}

public:
	void set_size_limit(size_t limit) { this->size_limit = limit; }
	size_t get_size_limit() const { return this->size_limit; }

protected:
	size_t size_limit;

public:
	ProtocolMessage() { this->size_limit = (size_t)-1; }
};

}

#endif


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

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <string>
#include "TLVMessage.h"

namespace protocol
{

int TLVMessage::encode(struct iovec vectors[], int max)
{
	this->head[0] = htonl((uint32_t)this->type);
	this->head[1] = htonl(this->value.size());

	vectors[0].iov_base = this->head;
	vectors[0].iov_len = 8;
	vectors[1].iov_base = (char *)this->value.data();
	vectors[1].iov_len = this->value.size();
	return 2;
}

int TLVMessage::append(const void *buf, size_t *size)
{
	size_t n = *size;
	size_t head_left;

	head_left = 8 - this->head_received;
	if (head_left > 0)
	{
		void *p = (char *)this->head + this->head_received;

		if (n < head_left)
		{
			memcpy(p, buf, n);
			this->head_received += n;
			return 0;
		}

		memcpy(p, buf, head_left);
		this->head_received = 8;
		buf = (const char *)buf + head_left;
		n -= head_left;

		this->type = (int)ntohl(this->head[0]);
		*this->head = ntohl(this->head[1]);
		if (*this->head > this->size_limit)
		{
			errno = EMSGSIZE;
			return -1;
		}

		this->value.reserve(*this->head);
	}

	if (this->value.size() + n > *this->head)
	{
		n = *this->head - this->value.size();
		*size = n + head_left;
	}

	this->value.append((const char *)buf, n);
	return this->value.size() == *this->head;
}

}


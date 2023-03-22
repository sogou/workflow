/*
  Copyright (c) 2020 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

	  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Xie Han (xiehan@sogou-inc.com;63350856@qq.com)
*/

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <utility>
#include "message.h"

namespace protocol
{

int TutorialMessage::encode(struct iovec vectors[], int max/*max==8192*/)
{
	uint32_t n = htonl(this->body_size);

	memcpy(this->head, &n, 4);
	vectors[0].iov_base = this->head;
	vectors[0].iov_len = 4;
	vectors[1].iov_base = this->body;
	vectors[1].iov_len = this->body_size;

	return 2;	/* return the number of vectors used, no more then max. */
}

int TutorialMessage::append(const void *buf, size_t size)
{
	if (this->head_received < 4)
	{
		size_t head_left;
		void *p;

		p = &this->head[head_received];
		head_left = 4 - this->head_received;
		if (size < 4 - this->head_received)
		{
			memcpy(p, buf, size);
			this->head_received += size;
			return 0;
		}
		this->head_received += head_left;

		memcpy(p, buf, head_left);
		size -= head_left;
		buf = (const char *)buf + head_left;

		p = this->head;
		this->body_size = ntohl(*(uint32_t *)p);
		if (this->body_size > this->size_limit)
		{
			errno = EMSGSIZE;
			return -1;
		}

		this->body = (char *)malloc(this->body_size);
		if (!this->body)
			return -1;

		this->body_received = 0;
	}

	size_t body_left = this->body_size - this->body_received;

	if (size > body_left)
	{
		errno = EBADMSG;
		return -1;
	}

	memcpy(this->body + this->body_received, buf, size);
	this->body_received += size;
	if (size < body_left)
		return 0;

	return 1;
}

int TutorialMessage::set_message_body(const void *body, size_t size)
{
	void *p = malloc(size);

	if (!p)
		return -1;

	memcpy(p, body, size);
	free(this->body);
	this->body = (char *)p;
	this->body_size = size;

	this->head_received = 4;
	this->body_received = size;
	return 0;
}

TutorialMessage::TutorialMessage(TutorialMessage&& msg) :
	ProtocolMessage(std::move(msg))
{
	memcpy(this->head, msg.head, 4);
	this->head_received = msg.head_received;
	this->body = msg.body;
	this->body_received = msg.body_received;
	this->body_size = msg.body_size;

	msg.head_received = 0;
	msg.body = NULL;
	msg.body_size = 0;
}

TutorialMessage& TutorialMessage::operator = (TutorialMessage&& msg)
{
	if (&msg != this)
	{
		*(ProtocolMessage *)this = std::move(msg);

		memcpy(this->head, msg.head, 4);
		this->head_received = msg.head_received;
		this->body = msg.body;
		this->body_received = msg.body_received;
		this->body_size = msg.body_size;

		msg.head_received = 0;
		msg.body = NULL;
		msg.body_size = 0;
	}

	return *this;
}

}


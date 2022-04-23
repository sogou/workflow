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
#include <utility>
#include "Communicator.h"

/**
 * @file   ProtocolMessage.h
 * @brief  General Protocol Interface
 */

namespace protocol
{

class ProtocolMessage : public CommMessageOut, public CommMessageIn
{
protected:
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

public:
	class Attachment
	{
	public:
		virtual ~Attachment() { }
	};

	void set_attachment(Attachment *att) { this->attachment = att; }
	Attachment *get_attachment() const { return this->attachment; }

protected:
	virtual int feedback(const void *buf, size_t size)
	{
		if (this->wrapper)
			return this->wrapper->feedback(buf, size);
		else
			return this->CommMessageIn::feedback(buf, size);
	}

	virtual void renew()
	{
		if (this->wrapper)
			return this->wrapper->renew();
		else
			return this->CommMessageIn::renew();
	}

protected:
	size_t size_limit;

private:
	Attachment *attachment;
	ProtocolMessage *wrapper;

public:
	ProtocolMessage()
	{
		this->size_limit = (size_t)-1;
		this->attachment = NULL;
		this->wrapper = NULL;
	}

	virtual ~ProtocolMessage() { delete this->attachment; }

public:
	ProtocolMessage(ProtocolMessage&& msg)
	{
		this->size_limit = msg.size_limit;
		msg.size_limit = (size_t)-1;
		this->attachment = msg.attachment;
		msg.attachment = NULL;
	}

	ProtocolMessage& operator = (ProtocolMessage&& msg)
	{
		if (&msg != this)
		{
			this->size_limit = msg.size_limit;
			msg.size_limit = (size_t)-1;
			delete this->attachment;
			this->attachment = msg.attachment;
			msg.attachment = NULL;
		}

		return *this;
	}

	friend class ProtocolWrapper;
};

class ProtocolWrapper : public ProtocolMessage
{
protected:
	virtual int encode(struct iovec vectors[], int max)
	{
		return this->msg->encode(vectors, max);
	}

	virtual int append(const void *buf, size_t *size)
	{
		return this->msg->append(buf, size);
	}

protected:
	ProtocolMessage *msg;

public:
	ProtocolWrapper(ProtocolMessage *msg)
	{
		msg->wrapper = this;
		this->msg = msg;
	}

public:
	ProtocolWrapper(ProtocolWrapper&& wrapper) :
		ProtocolMessage(std::move(wrapper))
	{
		wrapper.msg->wrapper = this;
		this->msg = wrapper.msg;
		wrapper.msg = NULL;
	}

	ProtocolWrapper& operator = (ProtocolWrapper&& wrapper)
	{
		if (&wrapper != this)
		{
			*(ProtocolMessage *)this = std::move(wrapper);
			wrapper.msg->wrapper = this;
			this->msg = wrapper.msg;
			wrapper.msg = NULL;
		}

		return *this;
	}
};

}

#endif


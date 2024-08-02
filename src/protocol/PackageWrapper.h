/*
  Copyright (c) 2022 Sogou, Inc.

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

#ifndef _PACKAGEWRAPPER_H_
#define _PACKAGEWRAPPER_H_

#include "ProtocolMessage.h"

namespace protocol
{

class PackageWrapper : public ProtocolWrapper
{
private:
	virtual ProtocolMessage *next_in(ProtocolMessage *message)
	{
		return this->next(message);
	}

	virtual ProtocolMessage *next_out(ProtocolMessage *message)
	{
		return this->next(message);
	}

	virtual ProtocolMessage *next(ProtocolMessage *message)
	{
		return NULL;
	}

protected:
	virtual int encode(struct iovec vectors[], int max);
	virtual int append(const void *buf, size_t *size);

public:
	PackageWrapper(ProtocolMessage *message) : ProtocolWrapper(message)
	{
	}

public:
	PackageWrapper(PackageWrapper&& wrapper) = default;
	PackageWrapper& operator = (PackageWrapper&& wrapper) = default;
};

}

#endif


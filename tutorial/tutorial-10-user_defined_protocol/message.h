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

#ifndef _TUTORIALMESSAGE_H_
#define _TUTORIALMESSAGE_H_

#include <stdlib.h>
#include "workflow/ProtocolMessage.h"

namespace protocol
{

class TutorialMessage : public ProtocolMessage
{
private:
	virtual int encode(struct iovec vectors[], int max);
	virtual int append(const void *buf, size_t size);

public:
	int set_message_body(const void *body, size_t size);

	void get_message_body_nocopy(void **body, size_t *size)
	{
		*body = this->body;
		*size = this->body_size;
	}

protected:
	char head[4];
	size_t head_received;
	char *body;
	size_t body_received;
	size_t body_size;

public:
	TutorialMessage()
	{
		this->head_received = 0;
		this->body = NULL;
		this->body_size = 0;
	}

	TutorialMessage(TutorialMessage&& msg);
	TutorialMessage& operator = (TutorialMessage&& msg);

	virtual ~TutorialMessage()
	{
		free(this->body);
	}
};

using TutorialRequest = TutorialMessage;
using TutorialResponse = TutorialMessage;

}

#endif


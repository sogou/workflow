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

  Author: Xie Han (xiehan@sogou-inc.com)
*/

#include <errno.h>
#include "CommScheduler.h"
#include "TransRequest.h"

void ChanRequest::dispatch()
{
	if (!this->established)
	{
		if (this->scheduler->establish(this, this->object, this->wait_timeout,
									   &this->target) < 0)
		{
			this->state = CS_STATE_ERROR;
			this->error = errno;
			this->subtask_done();
		}
	}
	else
		this->scheduler->shutdown(this);
}

void TransRequest::dispatch()
{
	int ret = this->scheduler->send(this, this->channel);

	if (ret == 0)
		return;

	if (ret > 0)
	{
		this->state = CS_STATE_SUCCESS;
		this->error = 0;
	}
	else
	{
		this->state = CS_STATE_ERROR;
		this->error = errno;
	}

	this->subtask_done();
}


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

#include <errno.h>
#include "PackageWrapper.h"

namespace protocol
{

int PackageWrapper::encode(struct iovec vectors[], int max)
{
	int cnt = 0;
	int ret;

	while (max >= 8)
	{
		ret = this->ProtocolWrapper::encode(vectors, max);
		if ((unsigned int)ret > (unsigned int)max)
		{
			if (ret < 0)
				return ret;

			break;
		}

		cnt += ret;
		this->set_message(this->next_out(this->message));
		if (!this->message)
			return cnt;

		vectors += ret;
		max -= ret;
	}

	errno = EOVERFLOW;
	return -1;
}

int PackageWrapper::append(const void *buf, size_t *size)
{
	int ret = this->ProtocolWrapper::append(buf, size);

	if (ret > 0)
	{
		this->set_message(this->next_in(this->message));
		if (this->message)
		{
			this->renew();
			ret = 0;
		}
	}

	return ret;
}

}


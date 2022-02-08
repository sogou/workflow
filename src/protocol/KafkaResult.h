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

  Authors: Wang Zhulei (wangzhulei@sogou-inc.com)
*/

#ifndef _KAFKARESULT_H_
#define _KAFKARESULT_H_

#include <map>
#include <vector>
#include <string>
#include "KafkaMessage.h"
#include "KafkaDataTypes.h"

namespace protocol
{

class KafkaResult
{
public:
	// for offsetcommit
	void fetch_toppars(std::vector<KafkaToppar *>& toppars);

	// for produce, fetch
	void fetch_records(std::vector<std::vector<KafkaRecord *>>& records);

public:
	void create(size_t n);

	void set_resp(KafkaResponse&& resp, size_t i);

public:
	KafkaResult();

	virtual ~KafkaResult()
	{
		delete []this->resp_vec;
	}

	KafkaResult& operator= (KafkaResult&& move);

	KafkaResult(KafkaResult&& move);

private:
	KafkaResponse *resp_vec;
	size_t resp_num;
};

}

#endif


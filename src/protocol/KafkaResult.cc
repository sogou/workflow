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

#include "KafkaResult.h"

namespace protocol
{

enum
{
	KAFKA_STATUS_GET_RESULT,
	KAFKA_STATUS_END,
};

KafkaResult::KafkaResult()
{
	this->resp_vec = NULL;
	this->resp_num = 0;
}

KafkaResult& KafkaResult::operator= (KafkaResult&& move)
{
	if (this != &move)
	{
		delete []this->resp_vec;

		this->resp_vec = move.resp_vec;
		move.resp_vec = NULL;

		this->resp_num = move.resp_num;
		move.resp_num = 0;
	}

	return *this;
}

KafkaResult::KafkaResult(KafkaResult&& move)
{
	this->resp_vec = move.resp_vec;
	move.resp_vec = NULL;

	this->resp_num = move.resp_num;
	move.resp_num = 0;
}

void KafkaResult::create(size_t n)
{
	delete []this->resp_vec;
	this->resp_vec = new KafkaResponse[n];
	this->resp_num = n;
}

void KafkaResult::set_resp(KafkaResponse&& resp, size_t i)
{
	assert(i < this->resp_num);
	this->resp_vec[i] = std::move(resp);
}

void KafkaResult::fetch_toppars(std::vector<KafkaToppar *>& toppars)
{
	toppars.clear();

	KafkaToppar *toppar = NULL;
	for (size_t i = 0; i < this->resp_num; ++i)
	{
		this->resp_vec[i].get_toppar_list()->rewind();

		while ((toppar = this->resp_vec[i].get_toppar_list()->get_next()) != NULL)
			toppars.push_back(toppar);
	}
}

void KafkaResult::fetch_records(std::vector<std::vector<KafkaRecord *>>& records)
{
	records.clear();

	KafkaToppar *toppar = NULL;
	KafkaRecord *record = NULL;

	for (size_t i = 0; i < this->resp_num; ++i)
	{
		if (this->resp_vec[i].get_api_type() != Kafka_Produce &&
			this->resp_vec[i].get_api_type() != Kafka_Fetch)
			continue;

		this->resp_vec[i].get_toppar_list()->rewind();

		while ((toppar = this->resp_vec[i].get_toppar_list()->get_next()) != NULL)
		{
			std::vector<KafkaRecord *> tmp;
			toppar->record_rewind();

			while ((record = toppar->get_record_next()) != NULL)
				tmp.push_back(record);

			if (!tmp.empty())
				records.emplace_back(std::move(tmp));
		}
	}
}

}


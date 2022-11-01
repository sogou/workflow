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

#include <set>
#include "WFTaskFactory.h"
#include "KafkaMessage.h"

// Kafka internal task. For __ComplexKafkaTask usage only
using __WFKafkaTask = WFNetworkTask<protocol::KafkaRequest,
									protocol::KafkaResponse>;
using __kafka_callback_t = std::function<void (__WFKafkaTask *)>;

class __WFKafkaTaskFactory
{
public:
	/* __WFKafkaTask is create by __ComplexKafkaTask. This is an internal
	 * interface for create internal task. It should not be created directly by common
	 * user task.
	 */
	static __WFKafkaTask *create_kafka_task(const ParsedURI& uri,
											int retry_max,
											__kafka_callback_t callback);

	static __WFKafkaTask *create_kafka_task(const std::string& url,
											int retry_max,
											__kafka_callback_t callback);

	static __WFKafkaTask *create_kafka_task(const struct sockaddr *addr,
											socklen_t addrlen,
											const std::string& info,
											int retry_max,
											__kafka_callback_t callback);

	static __WFKafkaTask *create_kafka_task(const char *host,
											unsigned short port,
											const std::string& info,
											int retry_max,
											__kafka_callback_t callback);
};

struct __ComplexKafkaTaskCtx
{
	int kafka_error;
	__kafka_callback_t cb;
};


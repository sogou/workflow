/*
  Copyright (c) 2024 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Authors: Xie Han (xiehan@sogou-inc.com)
*/

#include "WFTaskFactory.h"

// Internal, for WFRedisSubscribeTask only.

class __WFRedisTaskFactory
{
private:
	using extract_t = std::function<void (WFRedisTask *)>;

public:
	static WFRedisTask *create_subscribe_task(const std::string& url,
											  extract_t extract,
											  redis_callback_t callback);

	static WFRedisTask *create_subscribe_task(const ParsedURI& uri,
											  extract_t extract,
											  redis_callback_t callback);
};


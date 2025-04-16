/*
  Copyright (c) 2025 Sogou, Inc.

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

// Internal, for WFHttpChunkedTask only.

class __WFHttpTaskFactory
{
private:
	using chunked_t = std::function<void (WFHttpTask *)>;

public:
	static WFHttpTask *create_chunked_task(const std::string& url,
										   int redirect_max,
										   chunked_t chunked,
										   http_callback_t callback);

	static WFHttpTask *create_chunked_task(const ParsedURI& uri,
										   int redirect_max,
										   chunked_t chunked,
										   http_callback_t callback);
};


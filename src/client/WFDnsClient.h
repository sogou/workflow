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

  Author: Liu Kai (liukaidx@sogou-inc.com)
*/

#ifndef _WFDNSCLIENT_H_
#define _WFDNSCLIENT_H_

#include <string>
#include <atomic>
#include "WFTaskFactory.h"
#include "DnsMessage.h"

class WFDnsClient
{
public:
	int init(const std::string& url);
	int init(const std::string& url, const std::string& search_list,
			 int ndots, int attempts, bool rotate);
	void deinit();

	WFDnsTask *create_dns_task(const std::string& name,
							   dns_callback_t callback);

private:
	void *params;
	std::atomic<size_t> id;

public:
	virtual ~WFDnsClient() { }
};

#endif


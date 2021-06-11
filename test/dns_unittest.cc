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

#include <future>
#include <gtest/gtest.h>
#include "workflow/WFTaskFactory.h"
#include "workflow/WFDnsClient.h"

#define RETRY_MAX	3

TEST(dns_unittest, WFDnsTaskCreate1)
{
	std::string url = "dns://119.29.29.29/www.sogou.com";
	auto *task = WFTaskFactory::create_dns_task(url, 0, NULL);
	task->dismiss();
}

TEST(dns_unittest, WFDnsTaskCreate2)
{
	std::string url = "http://119.29.29.29:dns/";
	std::promise<void> done;
	auto *task = WFTaskFactory::create_dns_task(url, 0,
	[&done] (WFDnsTask *task)
	{
		done.set_value();
	});
	task->start();
	done.get_future().get();
}

TEST(dns_unittest, WFDnsTask)
{
	std::string url = "dns://119.29.29.29/www.sogou.com";
	unsigned short req_id = 0x1234;
	std::promise<void> done;

	auto *task = WFTaskFactory::create_dns_task(url, RETRY_MAX,
	[&done, req_id] (WFDnsTask *task)
	{
		int state = task->get_state();

		if (state == WFT_STATE_SUCCESS)
		{
			unsigned short resp_id = task->get_resp()->get_id();
			EXPECT_TRUE(req_id == resp_id);
		}

		done.set_value();
	});

	auto *req = task->get_req();
	req->set_id(req_id);
	req->set_rd(1);
	req->set_question_type(DNS_TYPE_A);
	task->start();

	auto fut = done.get_future();
	fut.get();
}

TEST(dns_unittest, WFDnsClientInit1)
{
	WFDnsClient client;
	if (client.init("bad") >= 0)
		client.deinit();
}

TEST(dns_unittest, WFDnsClientInit2)
{
	WFDnsClient client;
	int ret = client.init("0.0.0.0,0.0.0.1:1,dns://0.0.0.2,dnss://0.0.0.3");
	EXPECT_TRUE(ret >= 0);
	client.deinit();
}

TEST(dns_unittest, WFDnsClient)
{
	unsigned short req_id = 0x4321;
	std::promise<void> done;
	WFDnsClient client;

	client.init("dns://119.29.29.29/");

	auto *task = client.create_dns_task("www.sogou.com",
	[&done, req_id] (WFDnsTask *task)
	{
		int state = task->get_state();

		if (state == WFT_STATE_SUCCESS)
		{
			unsigned short resp_id = task->get_resp()->get_id();
			EXPECT_TRUE(req_id == resp_id);
		}

		done.set_value();
	});

	client.deinit();

	auto *req = task->get_req();
	req->set_id(req_id);
	task->start();

	auto fut = done.get_future();
	fut.get();
}

int main(int argc, char *argv[])
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

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

  Author: Li Yingxin (liyingxin@sogou-inc.com)
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <chrono>
#include <gtest/gtest.h>
#include "workflow/WFFacilities.h"
#include "workflow/HttpUtil.h"

#define GET_CURRENT_MICRO	std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()

TEST(facilities_unittest, usleep)
{
	int64_t st = GET_CURRENT_MICRO;
	WFFacilities::usleep(1000000);
	int64_t ed = GET_CURRENT_MICRO;
	EXPECT_LE(ed - st, 10000000) << "usleep too slow";
}

TEST(facilities_unittest, async_usleep)
{
	int64_t st = GET_CURRENT_MICRO;
	WFFacilities::async_usleep(1000000).wait();
	int64_t ed = GET_CURRENT_MICRO;
	EXPECT_LE(ed - st, 10000000) << "async_usleep too slow";
}

TEST(facilities_unittest, request)
{
	protocol::HttpRequest req;
	req.set_method(HttpMethodGet);
	req.set_http_version("HTTP/1.1");
	req.set_request_uri("/");
	req.set_header_pair("Host", "github.com");
	auto res = WFFacilities::request<protocol::HttpRequest, protocol::HttpResponse>(TT_TCP, "http://github.com", std::move(req), 0);
	//EXPECT_EQ(res.task_state, WFT_STATE_SUCCESS);
	if (res.task_state == WFT_STATE_SUCCESS)
	{
		auto code = atoi(res.resp.get_status_code());
		EXPECT_TRUE(code == HttpStatusOK ||
					code == HttpStatusMovedPermanently ||
					code == HttpStatusFound ||
					code == HttpStatusSeeOther ||
					code == HttpStatusTemporaryRedirect ||
					code == HttpStatusPermanentRedirect);
	}
}

TEST(facilities_unittest, async_request)
{
	protocol::HttpRequest req;
	req.set_method(HttpMethodGet);
	req.set_http_version("HTTP/1.1");
	req.set_request_uri("/");
	req.set_header_pair("Host", "github.com");
	auto res = WFFacilities::request<protocol::HttpRequest, protocol::HttpResponse>(TT_TCP_SSL, "https://github.com", std::move(req), 0);
	//EXPECT_EQ(res.task_state, WFT_STATE_SUCCESS);
	if (res.task_state == WFT_STATE_SUCCESS)
	{
		auto code = atoi(res.resp.get_status_code());
		EXPECT_TRUE(code == HttpStatusOK ||
					code == HttpStatusMovedPermanently ||
					code == HttpStatusFound ||
					code == HttpStatusSeeOther ||
					code == HttpStatusTemporaryRedirect ||
					code == HttpStatusPermanentRedirect);
	}
}

TEST(facilities_unittest, fileIO)
{
	uint64_t data = 0x1234;
	ssize_t sz;
	int fd = open("test.test", O_RDWR | O_TRUNC | O_CREAT, 0644);

	sz = WFFacilities::async_pwrite(fd, &data, 8, 0).get();
	EXPECT_EQ(sz, 8);
	data = 0;
	sz = WFFacilities::async_pread(fd, &data, 8, 0).get();
	EXPECT_EQ(sz, 8);
	EXPECT_EQ(data, 0x1234);
	close(fd);
}

static inline void f(int i, WFFacilities::WaitGroup *wg)
{
	wg->done();
}

TEST(facilities_unittest, WaitGroup)
{
	WFFacilities::WaitGroup wg(100);

	for (int i = 0; i < 100; i++)
		WFFacilities::go("facilities", f, i, &wg);

	wg.wait();

	WFFacilities::WaitGroup wg2(-100);
	wg2.wait();

	WFFacilities::WaitGroup wg3(0);
	wg3.wait();
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L

#include <openssl/ssl.h>
int main(int argc, char* argv[])
{
	OPENSSL_init_ssl(0, 0);
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

#endif

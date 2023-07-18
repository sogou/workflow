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

  Author: Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

#include <mutex>
#include <condition_variable>
#include <chrono>
#include <gtest/gtest.h>
#include "workflow/WFTaskFactory.h"
#include "workflow/WFOperator.h"
#include "workflow/WFHttpServer.h"
#include "workflow/HttpUtil.h"

#define RETRY_MAX  3

static void __http_process(WFHttpTask *task)
{
	auto *req = task->get_req();
	auto *resp = task->get_resp();

	EXPECT_TRUE(strcmp(req->get_request_uri(), "/test") == 0);
	resp->add_header_pair("Content-Type", "text/plain");
}

TEST(http_unittest, WFHttpTask1)
{
	std::mutex mutex;
	std::condition_variable cond;
	bool done = false;
	auto *task = WFTaskFactory::create_http_task("http://github.com", 0, RETRY_MAX, [&mutex, &cond, &done](WFHttpTask *task) {
		auto state = task->get_state();

		//EXPECT_EQ(state, WFT_STATE_SUCCESS);
		if (state == WFT_STATE_SUCCESS)
		{
			auto code = atoi(task->get_resp()->get_status_code());
			EXPECT_TRUE(code == HttpStatusOK ||
						code == HttpStatusMovedPermanently ||
						code == HttpStatusFound ||
						code == HttpStatusSeeOther ||
						code == HttpStatusTemporaryRedirect ||
						code == HttpStatusPermanentRedirect);
		}

		mutex.lock();
		done = true;
		mutex.unlock();
		cond.notify_one();
	});
	task->start();

	std::unique_lock<std::mutex> lock(mutex);
	while (!done)
		cond.wait(lock);

	lock.unlock();
}

TEST(http_unittest, WFHttpTask2)
{
	std::mutex mutex;
	std::condition_variable cond;
	bool done = false;
	auto *task = WFTaskFactory::create_http_task("http://github.com", 1, RETRY_MAX, [&mutex, &cond, &done](WFHttpTask *task) {
		auto state = task->get_state();

		//EXPECT_EQ(state, WFT_STATE_SUCCESS);
		if (state == WFT_STATE_SUCCESS)
		{
			auto code = atoi(task->get_resp()->get_status_code());
			EXPECT_TRUE(code == HttpStatusOK ||
						code == HttpStatusMovedPermanently ||
						code == HttpStatusFound ||
						code == HttpStatusSeeOther ||
						code == HttpStatusTemporaryRedirect ||
						code == HttpStatusPermanentRedirect);
		}

		mutex.lock();
		done = true;
		mutex.unlock();
		cond.notify_one();
	});
	task->start();

	std::unique_lock<std::mutex> lock(mutex);
	while (!done)
		cond.wait(lock);

	lock.unlock();
}

TEST(http_unittest, WFHttpTask3)
{
	FILE *f;
	f = fopen("server.crt", "w");
	fputs(R"(
-----BEGIN CERTIFICATE-----
MIIDrjCCApYCCQCzDnhp/eqaRTANBgkqhkiG9w0BAQUFADCBmDELMAkGA1UEBhMC
Q04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWppbmcxFzAVBgNVBAoM
DlNvZ291LmNvbSBJbmMuMRYwFAYDVQQLDA13d3cuc29nb3UuY29tMQ8wDQYDVQQD
DAZ4aWVoYW4xIzAhBgkqhkiG9w0BCQEWFHhpZWhhbkBzb2dvdS1pbmMuY29tMB4X
DTE5MDYxMTA5MjQxNloXDTIwMDYxMDA5MjQxNlowgZgxCzAJBgNVBAYTAkNOMRAw
DgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdCZWlqaW5nMRcwFQYDVQQKDA5Tb2dv
dS5jb20gSW5jLjEWMBQGA1UECwwNd3d3LnNvZ291LmNvbTEPMA0GA1UEAwwGeGll
aGFuMSMwIQYJKoZIhvcNAQkBFhR4aWVoYW5Ac29nb3UtaW5jLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBALB6E1+lnuey24j+BwcD21h5t/xD+K6I
thHiyT3S8fztAd+BfyphT+KLhbHbJFUaz7tfoV8lyBDdyVlgfwlCLyCp2sNcaCwg
TF+XjTWOkDtg5+rCgoHRUjLNIJ2auO/5780DZcaL41gwzAu5rwE3sOifIZ4XI5WO
6zrd5MUFhpHy91Sz1sxcCLXwQEgPDsa10/6k5bSd8xYP29yZ80lZeJ++5fgOf/AU
JkANXLjsHnfOFV42Je/6EEcqe0YM6kjA9d4d5TS+To5YPfObTTR21Cey4RD5Ijjg
4/VGdtI6tDWa3+N/CVVc8CKLVGNCVyAGWoBXCZuzlfex9Z0jtY2dd1cCAwEAATAN
BgkqhkiG9w0BAQUFAAOCAQEAoLALHvGt0xCsDsYxxQ3biioPa2djT5jN8/QI17QF
7C+0IdFEJi6dwF/O0rPgHbVSMZB7pPl5gx/rC4bWg9CYvZmlptmDJym+SpR0CBLC
/LXEFsA7VmkdAiG6CHLtg1uZy0LTN0sRMdLNIetm6PBcnr3JEB8erayRaYy1Qk7d
6O+3KexviFX/dAJRj59AIYXoMwji2ZYowXH+InNVF8UEunynJGURJJGQXFh0R18Q
SniEJZux/WkxaOkqMBHtXtdkowpSMjn/RUA5dVu5Zjyf8LL9cjBmyKMxLXKeQeKK
0ylFmFZxY8GawFdCq4XUKzSuLw4/orfuKn/ViSSixuXL5A==
-----END CERTIFICATE-----
)", f);
	fclose(f);
	f = fopen("server.key", "w");
	fputs(R"(
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAsHoTX6We57LbiP4HBwPbWHm3/EP4roi2EeLJPdLx/O0B34F/
KmFP4ouFsdskVRrPu1+hXyXIEN3JWWB/CUIvIKnaw1xoLCBMX5eNNY6QO2Dn6sKC
gdFSMs0gnZq47/nvzQNlxovjWDDMC7mvATew6J8hnhcjlY7rOt3kxQWGkfL3VLPW
zFwItfBASA8OxrXT/qTltJ3zFg/b3JnzSVl4n77l+A5/8BQmQA1cuOwed84VXjYl
7/oQRyp7RgzqSMD13h3lNL5Ojlg985tNNHbUJ7LhEPkiOODj9UZ20jq0NZrf438J
VVzwIotUY0JXIAZagFcJm7OV97H1nSO1jZ13VwIDAQABAoIBAFPW+yNCjLaouzFe
9bm4dFmZIfZf2GIaotzmcBLGB57QfkZPwDlDF++Ztz9iy+T+otfyu7h3O4//veuP
M2sTnU4YQ8zyNq9X/NChMD3UZ+M9y5A1Lkk8R5/I4gjd+6ROikVMqupjhPNd42Ji
qaiba5loGFGBzq77wfcqece8M01cZTnCtZ5ZdFrxzWWd9EaKhXf6Mkibaf6Y4/Oi
GVvhqKK7Yv4f+xX85GnZuBv8hau6nCfiC/5zYKm8SiAoWE1TikMZGd2+bwAE1COh
qeVJyevA7XcP8z+dtqb0hBHqlm0DTyVmu/cuHAZHxYms7VvJ2isWKI4gl1MY3zD3
ODHEeHECgYEA36eVhGCAQeAP3eTtEq1dcSSsb3bEKTpZGxj6BT89HRp0qcw/dKQV
oITXMeSJpIRR879mi5FBFHlvTb0xkI96O5fXuAz/A7hSOtZpiJ4G3tAEplbPJhmB
3km3syRXqXuv8m38Zjb9FOgu7D/OSWYe8QGWM/rrDjgBfJNveKlWn/kCgYEAyf/R
heAvuFxqf77XRzjBhil1N09f9mw8yagFritNyy8Wb+SlNSHIBZ9WSKVdVxyA4GOe
A/0yAY7r9i/Y1sMnCt0kL5UEwY2xlbA+Ld/B/5MjEN4mP9g5a2goj75w7CBT/YLh
dAfNwN08wsTNl/53tovhqz1uvU+muAWQnAgURc8CgYAjqKOFHKG2XxQIi+RkkvGQ
BYncp7H05NGqKVxLk96ZkktBe0guv66XDjcFRGvRqCss0rp1zC31JrthSKXrZ4TU
lYwWUzQhkrTBnsfquU9dHQtwvex/JZf4Kga48DVt10OhQnn4jhHh0HcSwcWRHFAY
muko1nu9o55RD2y5bz5ZeQKBgFfzec/3n+9+1aQPfP52uNRogq/1cIwD7qfC7844
7qNUOkm33TL4JXZFPTVeQvjl4TtSRH/qI3bIOvczOA+yYvJ4/QN2t95qinLpjPk+
XuKftvnmL/NGeyHH9Tk5K0O0g71y2iVCLJUX/xeyxu2yD3+9AiIkGm51GtsvGRrG
7cTDAoGAIlzSgiMSMkRUpzyJYvRd5o+Bt+v+SHDni40XrfZqc4cmh8MVPdVkNMFi
a/7MiJf+tw5lRG/Oks0pNOvFIpTXi8ncxW9tgQfy2hN6LMGD7uIu/X9uMJmwvNtj
KZ1lOvb+vi3TLrQf4tfBekrXXe5tZK40QSJ7UdtY7HHrrbAXU+8=
-----END RSA PRIVATE KEY-----
)", f);
	fclose(f);

	WFHttpServer http_server(__http_process);
	EXPECT_TRUE(http_server.start("127.0.0.1", 8811) == 0) << "http server start failed";

	WFHttpServer https_server(__http_process);
	EXPECT_TRUE(https_server.start("127.0.0.1", 8822, "server.crt", "server.key") == 0) << "https server start failed";

	std::mutex mutex;
	std::condition_variable cond;
	bool done = false;
	auto cb = [](WFHttpTask *task) {
		auto state = task->get_state();

		EXPECT_EQ(state, WFT_STATE_SUCCESS);
		if (state == WFT_STATE_SUCCESS)
		{
			auto *resp = task->get_resp();
			auto code = atoi(resp->get_status_code());
			EXPECT_EQ(code, HttpStatusOK);
			protocol::HttpHeaderCursor cursor(resp);
			std::string content_type;
			EXPECT_TRUE(cursor.find("Content-Type", content_type));
			EXPECT_TRUE(content_type == "text/plain");
		}
	};

	auto *A = WFTaskFactory::create_http_task("http://127.0.0.1:8811/test", 0, RETRY_MAX, cb);
	auto *B = WFTaskFactory::create_http_task("https://127.0.0.1:8822/test", 0, RETRY_MAX, cb);
	auto& flow = *A > B;

	flow.set_callback([&mutex, &cond, &done](const SeriesWork *series) {
		mutex.lock();
		done = true;
		mutex.unlock();
		cond.notify_one();
	});

	flow.start();
	std::unique_lock<std::mutex> lock(mutex);
	while (!done)
		cond.wait(lock);

	lock.unlock();
	http_server.stop();
	https_server.stop();
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

/*
  Copyright (c) 2019 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Authors: Wu Jiaxu (wujiaxu@sogou-inc.com)
           Li Yingxin (liyingxin@sogou-inc.com)
*/

#include <assert.h>
#include <string>
#include "WFTaskError.h"
#include "WFTaskFactory.h"
#include "StringUtil.h"
#include "WFGlobal.h"
#include "HttpUtil.h"

using namespace protocol;

#define HTTP_KEEPALIVE_DEFAULT	(60 * 1000)
#define HTTP_KEEPALIVE_MAX		(300 * 1000)

/**********Client**********/

class ComplexHttpTask : public WFComplexClientTask<HttpRequest, HttpResponse>
{
public:
	ComplexHttpTask(int redirect_max,
					int retry_max,
					http_callback_t&& callback):
		WFComplexClientTask(retry_max, std::move(callback)),
		redirect_max_(redirect_max),
		redirect_count_(0)
	{
		HttpRequest *client_req = this->get_req();

		client_req->set_method(HttpMethodGet);
		client_req->set_http_version("HTTP/1.1");
	}

protected:
	virtual CommMessageOut *message_out();
	virtual CommMessageIn *message_in();
	virtual int keep_alive_timeout();
	virtual bool init_success();
	virtual void init_failed();
	virtual bool finish_once();

private:
	bool need_redirect();
	bool redirect_url(HttpResponse *client_resp);
	void set_empty_request();

	int redirect_max_;
	int redirect_count_;
};

CommMessageOut *ComplexHttpTask::message_out()
{
	auto *req = this->get_req();
	bool is_alive;
	HttpHeaderCursor req_cursor(req);
	struct HttpMessageHeader header;
	bool chunked = false;

	header.name = "Transfer-Encoding";
	header.name_len = 17;
	if (req_cursor.find(&header) && header.value_len > 0)
	{
		chunked = !(header.value_len == 8 &&
			strncasecmp((const char *)header.value, "identity", 8) == 0);
	}

	if (!chunked)
	{
		size_t body_size = req->get_output_body_size();
		const char *method = req->get_method();

		if (body_size != 0 || strcmp(method, "POST") == 0 || strcmp(method, "PUT") == 0)
		{
			header.name = "Content-Length";
			header.name_len = 14;
			req_cursor.rewind();
			if (!req_cursor.find(&header))
			{
				char buf[32];
				header.value = buf;
				header.value_len = sprintf(buf, "%zu", body_size);
				req->add_header(&header);
			}
		}
	}

	header.name = "Connection";
	header.name_len = 10;
	req_cursor.rewind();
	if (req_cursor.find(&header))
	{
		is_alive = (header.value_len == 10 &&
				strncasecmp((const char *)header.value, "Keep-Alive", 10) == 0);
	}
	else if (this->keep_alive_timeo != 0)
	{
		is_alive = true;
		header.value = "Keep-Alive";
		header.value_len = 10;
		req->add_header(&header);
	}
	else
	{
		is_alive = false;
		header.value = "close";
		header.value_len = 5;
		req->add_header(&header);
	}

	if (!is_alive)
		this->keep_alive_timeo = 0;
	else
	{
		//req---Connection: Keep-Alive
		//req---Keep-Alive: timeout=0,max=100

		header.name = "Keep-Alive";
		header.name_len = 10;
		req_cursor.rewind();
		if (req_cursor.find(&header))
		{
			std::string keep_alive((const char *)header.value, header.value_len);
			std::vector<std::string> params = StringUtil::split(keep_alive, ',');

			for (const auto& kv : params)
			{
				std::vector<std::string> arr = StringUtil::split(kv, '=');
				if (arr.size() < 2)
					arr.emplace_back("0");

				std::string key = StringUtil::strip(arr[0]);
				std::string val = StringUtil::strip(arr[1]);
				if (strcasecmp(key.c_str(), "timeout") == 0)
				{
					this->keep_alive_timeo = atoi(val.c_str());
					break;
				}
			}
		}

		if ((unsigned int)this->keep_alive_timeo > HTTP_KEEPALIVE_MAX)
			this->keep_alive_timeo = HTTP_KEEPALIVE_MAX;
		//if (this->keep_alive_timeo < 0 || this->keep_alive_timeo > HTTP_KEEPALIVE_MAX)
	}

	//req->set_header_pair("Accept", "*/*");
	return this->WFClientTask::message_out();
}

CommMessageIn *ComplexHttpTask::message_in()
{
	auto *resp = this->get_resp();

	if (strcmp(this->get_req()->get_method(), HttpMethodHead) == 0)
		resp->parse_zero_body();

	return this->WFClientTask::message_in();
}

int ComplexHttpTask::keep_alive_timeout()
{
	return this->resp.is_keep_alive() ? this->keep_alive_timeo : 0;
}

void ComplexHttpTask::set_empty_request()
{
	HttpRequest *client_req = this->get_req();
	client_req->set_request_uri("/");
	client_req->set_header_pair("Host", "");
}

void ComplexHttpTask::init_failed()
{
	this->set_empty_request();
}

bool ComplexHttpTask::init_success()
{
	HttpRequest *client_req = this->get_req();
	std::string request_uri;
	std::string header_host;
	bool is_ssl;
	bool is_unix = false;

	if (uri_.scheme && strcasecmp(uri_.scheme, "http") == 0)
		is_ssl = false;
	else if (uri_.scheme && strcasecmp(uri_.scheme, "https") == 0)
		is_ssl = true;
	else
	{
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_URI_SCHEME_INVALID;
		this->set_empty_request();
		return false;
	}

	//todo http+unix
	//https://stackoverflow.com/questions/26964595/whats-the-correct-way-to-use-a-unix-domain-socket-in-requests-framework
	//https://stackoverflow.com/questions/27037990/connecting-to-postgres-via-database-url-and-unix-socket-in-rails

	if (uri_.path && uri_.path[0])
		request_uri = uri_.path;
	else
		request_uri = "/";

	if (uri_.query && uri_.query[0])
	{
		request_uri += "?";
		request_uri += uri_.query;
	}

	if (uri_.host && uri_.host[0])
	{
		header_host = uri_.host;
		if (uri_.host[0] == '/')
			is_unix = true;
	}

	if (!is_unix && uri_.port && uri_.port[0])
	{
		int port = atoi(uri_.port);

		if (is_ssl)
		{
			if (port != 443)
			{
				header_host += ":";
				header_host += uri_.port;
			}
		}
		else
		{
			if (port != 80)
			{
				header_host += ":";
				header_host += uri_.port;
			}
		}
	}

	this->WFComplexClientTask::set_type(is_ssl ? TT_TCP_SSL : TT_TCP);
	client_req->set_request_uri(request_uri.c_str());
	client_req->set_header_pair("Host", header_host.c_str());

	return true;
}

bool ComplexHttpTask::redirect_url(HttpResponse *client_resp)
{
	if (redirect_count_ < redirect_max_)
	{
		redirect_count_++;
		std::string url;
		HttpHeaderCursor cursor(client_resp);

		if (!cursor.find("Location", url) || url.empty())
		{
			this->state = WFT_STATE_TASK_ERROR;
			this->error = WFT_ERR_HTTP_BAD_REDIRECT_HEADER;
			return false;
		}

		URIParser::parse(url, uri_);
		return true;
	}

	return false;
}

bool ComplexHttpTask::need_redirect()
{
	HttpRequest *client_req = this->get_req();
	HttpResponse *client_resp = this->get_resp();
	const char *status_code_str = client_resp->get_status_code();
	const char *method = client_req->get_method();

	if (!status_code_str || !method)
		return false;

	int status_code = atoi(status_code_str);

	switch (status_code)
	{
	case 301:
	case 302:
	case 303:
		if (redirect_url(client_resp))
		{
			if (strcasecmp(method, HttpMethodGet) != 0 &&
				strcasecmp(method, HttpMethodHead) != 0)
			{
				client_req->set_method(HttpMethodGet);
			}

			return true;
		}
		else
			break;

	case 307:
	case 308:
		if (redirect_url(client_resp))
			return true;
		else
			break;

	default:
		break;
	}

	return false;
}

bool ComplexHttpTask::finish_once()
{
	if (this->state == WFT_STATE_SUCCESS)
	{
		if (need_redirect())
			this->set_redirect(uri_);
		else if (this->state != WFT_STATE_SUCCESS)
			this->disable_retry();
	}
	else
	{
		this->get_resp()->end_parsing();
		redirect_count_ = 0;
	}

	return true;
}

/**********Client Factory**********/

WFHttpTask *WFTaskFactory::create_http_task(const std::string& url,
											int redirect_max,
											int retry_max,
											http_callback_t callback)
{
	auto *task = new ComplexHttpTask(redirect_max,
									 retry_max,
									 std::move(callback));
	ParsedURI uri;

	URIParser::parse(url, uri);
	task->init(std::move(uri));
	task->set_keep_alive(HTTP_KEEPALIVE_DEFAULT);
	return task;
}

WFHttpTask *WFTaskFactory::create_http_task(const ParsedURI& uri,
											int redirect_max,
											int retry_max,
											http_callback_t callback)
{
	auto *task = new ComplexHttpTask(redirect_max,
									 retry_max,
									 std::move(callback));

	task->init(uri);
	task->set_keep_alive(HTTP_KEEPALIVE_DEFAULT);
	return task;
}

/**********Server**********/

class WFHttpServerTask : public WFServerTask<HttpRequest, HttpResponse>
{
public:
	WFHttpServerTask(std::function<void (WFHttpTask *)>& process):
		WFServerTask(WFGlobal::get_scheduler(), process),
		req_is_alive_(false),
		req_header_has_keep_alive_(false)
	{}

protected:
	virtual void handle(int state, int error)
	{
		if (state == WFT_STATE_TOREPLY)
		{
			req_is_alive_ = this->req.is_keep_alive();
			if (req_is_alive_)
			{
				HttpHeaderCursor req_cursor(&this->req);
				struct HttpMessageHeader header;

				header.name = "Keep-Alive";
				header.name_len = 10;
				req_header_has_keep_alive_ = req_cursor.find(&header);
				if (req_header_has_keep_alive_)
					req_keep_alive_.assign((const char *)header.value,
											header.value_len);
			}
		}

		this->WFServerTask::handle(state, error);
	}

	virtual CommMessageOut *message_out();

private:
	bool req_is_alive_;
	bool req_header_has_keep_alive_;
	std::string req_keep_alive_;
};

CommMessageOut *WFHttpServerTask::message_out()
{
	auto *resp = this->get_resp();

	if (!resp->get_http_version())
		resp->set_http_version("HTTP/1.1");

	const char *status_code_str = resp->get_status_code();
	if (!status_code_str || !resp->get_reason_phrase())
	{
		int status_code;

		if (status_code_str)
			status_code = atoi(status_code_str);
		else
			status_code = HttpStatusOK;

		HttpUtil::set_response_status(resp, status_code);
	}

	HttpHeaderCursor resp_cursor(resp);
	struct HttpMessageHeader header;
	bool chunked = false;

	header.name = "Transfer-Encoding";
	header.name_len = 17;
	if (resp_cursor.find(&header) && header.value_len > 0)
	{
		chunked = !(header.value_len == 8 &&
			strncasecmp((const char *)header.value, "identity", 8) == 0);
	}

	size_t body_size = resp->get_output_body_size();

	if (!chunked)
	{
		header.name = "Content-Length";
		header.name_len = 14;
		resp_cursor.rewind();
		if (!resp_cursor.find(&header))
		{
			char buf[32];
			header.value = buf;
			header.value_len = sprintf(buf, "%zu", body_size);
			resp->add_header(&header);
		}
	}

	bool is_alive;
	bool resp_has_connection;

	header.name = "Connection";
	header.name_len = 10;
	resp_cursor.rewind();
	resp_has_connection = resp_cursor.find(&header);
	if (resp_has_connection)
	{
		is_alive = (header.value_len == 10 &&
				strncasecmp((const char *)header.value, "Keep-Alive", 10) == 0);
	}
	else
		is_alive = req_is_alive_;

	if (!is_alive)
		this->keep_alive_timeo = 0;
	else
	{
		//req---Connection: Keep-Alive
		//req---Keep-Alive: timeout=5,max=100

		if (req_header_has_keep_alive_)
		{
			int flag = 0;
			std::vector<std::string> params = StringUtil::split(req_keep_alive_, ',');

			for (const auto& kv : params)
			{
				std::vector<std::string> arr = StringUtil::split(kv, '=');
				if (arr.size() < 2)
					arr.emplace_back("0");

				std::string key = StringUtil::strip(arr[0]);
				std::string val = StringUtil::strip(arr[1]);
				if (!(flag & 1) && strcasecmp(key.c_str(), "timeout") == 0)
				{
					flag |= 1;
					this->keep_alive_timeo = atoi(val.c_str());
					if (flag == 3)
						break;
				}
				else if (!(flag & 2) && strcasecmp(key.c_str(), "max") == 0)
				{
					flag |= 2;
					if (this->get_seq() >= atoi(val.c_str()))
					{
						this->keep_alive_timeo = 0;
						break;
					}

					if (flag == 3)
						break;
				}
			}
		}

		if ((unsigned int)this->keep_alive_timeo > HTTP_KEEPALIVE_MAX)
			this->keep_alive_timeo = HTTP_KEEPALIVE_MAX;
		//if (this->keep_alive_timeo < 0 || this->keep_alive_timeo > HTTP_KEEPALIVE_MAX)

	}

	if (this->keep_alive_timeo == 0)
	{
		if (!resp_has_connection)
		{
			header.name = "Connection";
			header.name_len = 10;
			header.value = "close";
			header.value_len = 5;
			resp->add_header(&header);
		}
	}
	else
	{
		if (!resp_has_connection)
		{
			header.name = "Connection";
			header.name_len = 10;
			header.value = "Keep-Alive";
			header.value_len = 10;
			resp->add_header(&header);
		}
	}

	return this->WFServerTask::message_out();
}

/**********Server Factory**********/

WFHttpTask *WFServerTaskFactory::create_http_task(std::function<void (WFHttpTask *)>& process)
{
	return new WFHttpServerTask(process);
}


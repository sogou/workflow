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
           Liu Kai (liukaidx@sogou-inc.com)
           Xie Han (xiehan@sogou-inc.com)
           Li Yingxin (liyingxin@sogou-inc.com)
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include "WFTaskError.h"
#include "WFTaskFactory.h"
#include "StringUtil.h"
#include "WFGlobal.h"
#include "HttpUtil.h"
#include "SSLWrapper.h"

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

protected:
	bool need_redirect(ParsedURI& uri);
	bool redirect_url(HttpResponse *client_resp, ParsedURI& uri);
	void set_empty_request();
	void check_response();

private:
	int redirect_max_;
	int redirect_count_;
};

CommMessageOut *ComplexHttpTask::message_out()
{
	HttpRequest *req = this->get_req();
	struct HttpMessageHeader header;
	bool is_alive;

	if (!req->is_chunked() && !req->has_content_length_header())
	{
		size_t body_size = req->get_output_body_size();
		const char *method = req->get_method();

		if (body_size != 0 || strcmp(method, "POST") == 0 ||
							  strcmp(method, "PUT") == 0)
		{
			char buf[32];
			header.name = "Content-Length";
			header.name_len = strlen("Content-Length");
			header.value = buf;
			header.value_len = sprintf(buf, "%zu", body_size);
			req->add_header(&header);
		}
	}

	if (req->has_connection_header())
		is_alive = req->is_keep_alive();
	else
	{
		header.name = "Connection";
		header.name_len = strlen("Connection");
		is_alive = (this->keep_alive_timeo != 0);
		if (is_alive)
		{
			header.value = "Keep-Alive";
			header.value_len = strlen("Keep-Alive");
		}
		else
		{
			header.value = "close";
			header.value_len = strlen("close");
		}

		req->add_header(&header);
	}

	if (!is_alive)
		this->keep_alive_timeo = 0;
	else if (req->has_keep_alive_header())
	{
		HttpHeaderCursor req_cursor(req);

		//req---Connection: Keep-Alive
		//req---Keep-Alive: timeout=0,max=100
		header.name = "Keep-Alive";
		header.name_len = strlen("Keep-Alive");
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
					this->keep_alive_timeo = 1000 * atoi(val.c_str());
					break;
				}
			}
		}

		if ((unsigned int)this->keep_alive_timeo > HTTP_KEEPALIVE_MAX)
			this->keep_alive_timeo = HTTP_KEEPALIVE_MAX;
	}

	return this->WFComplexClientTask::message_out();
}

CommMessageIn *ComplexHttpTask::message_in()
{
	HttpResponse *resp = this->get_resp();

	if (strcmp(this->get_req()->get_method(), HttpMethodHead) == 0)
		resp->parse_zero_body();

	return this->WFComplexClientTask::message_in();
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
		header_host = uri_.host;

	if (uri_.port && uri_.port[0])
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

	this->WFComplexClientTask::set_transport_type(is_ssl ? TT_TCP_SSL : TT_TCP);
	client_req->set_request_uri(request_uri.c_str());
	client_req->set_header_pair("Host", header_host.c_str());
	return true;
}

bool ComplexHttpTask::redirect_url(HttpResponse *client_resp, ParsedURI& uri)
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

		if (url[0] == '/')
		{
			if (url[1] != '/')
			{
				if (uri.port)
					url = ':' + (uri.port + url);

				url = "//" + (uri.host + url);
			}

			url = uri.scheme + (':' + url);
		}

		URIParser::parse(url, uri);
		return true;
	}

	return false;
}

bool ComplexHttpTask::need_redirect(ParsedURI& uri)
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
		if (redirect_url(client_resp, uri))
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
		if (redirect_url(client_resp, uri))
			return true;
		else
			break;

	default:
		break;
	}

	return false;
}

void ComplexHttpTask::check_response()
{
	HttpResponse *resp = this->get_resp();

	resp->end_parsing();
	if (this->state == WFT_STATE_SYS_ERROR && this->error == ECONNRESET)
	{
		/* Servers can end the message by closing the connection. */
		if (resp->is_header_complete() &&
			!resp->is_keep_alive() &&
			!resp->is_chunked() &&
			!resp->has_content_length_header())
		{
			this->state = WFT_STATE_SUCCESS;
			this->error = 0;
		}
	}
}

bool ComplexHttpTask::finish_once()
{
	if (this->state != WFT_STATE_SUCCESS)
		this->check_response();

	if (this->state == WFT_STATE_SUCCESS)
	{
		if (this->need_redirect(uri_))
			this->set_redirect(uri_);
		else if (this->state != WFT_STATE_SUCCESS)
			this->disable_retry();
	}

	return true;
}

/*******Proxy Client*******/

static int __encode_auth(const char *p, std::string& auth)
{
	size_t len = strlen(p);
	size_t base64_len = (len + 2) / 3 * 4;
	char *base64 = (char *)malloc(base64_len + 1);

	if (!base64)
		return -1;

	EVP_EncodeBlock((unsigned char *)base64, (const unsigned char *)p, len);
	auth.append("Basic ");
	auth.append(base64, base64_len);

	free(base64);
	return 0;
}

static SSL *__create_ssl(SSL_CTX *ssl_ctx)
{
	BIO *wbio;
	BIO *rbio;
	SSL *ssl;

	rbio = BIO_new(BIO_s_mem());
	if (rbio)
	{
		wbio = BIO_new(BIO_s_mem());
		if (wbio)
		{
			ssl = SSL_new(ssl_ctx);
			if (ssl)
			{
				SSL_set_bio(ssl, rbio, wbio);
				return ssl;
			}

			BIO_free(wbio);
		}

		BIO_free(rbio);
	}

	return NULL;
}

class ComplexHttpProxyTask : public ComplexHttpTask
{
public:
	ComplexHttpProxyTask(int redirect_max,
						 int retry_max,
						 http_callback_t&& callback):
		ComplexHttpTask(redirect_max, retry_max, std::move(callback)),
		is_user_request_(true)
	{ }

	void set_user_uri(ParsedURI&& uri) { user_uri_ = std::move(uri); }
	void set_user_uri(const ParsedURI& uri) { user_uri_ = uri; }

	virtual const ParsedURI *get_current_uri() const { return &user_uri_; }

protected:
	virtual CommMessageOut *message_out();
	virtual CommMessageIn *message_in();
	virtual int keep_alive_timeout();
	virtual bool init_success();
	virtual bool finish_once();

protected:
	virtual WFConnection *get_connection() const
	{
		WFConnection *conn = this->ComplexHttpTask::get_connection();

		if (conn && is_ssl_)
			return (SSLConnection *)conn->get_context();

		return conn;
	}

private:
	struct SSLConnection : public WFConnection
	{
		SSL *ssl;
		SSLHandshaker handshaker;
		SSLWrapper wrapper;
		SSLConnection(SSL *ssl) : handshaker(ssl), wrapper(&wrapper, ssl)
		{
			this->ssl = ssl;
		}
	};

	SSLHandshaker *get_ssl_handshaker() const
	{
		return &((SSLConnection *)this->get_connection())->handshaker;
	}

	SSLWrapper *get_ssl_wrapper(ProtocolMessage *msg) const
	{
		SSLConnection *conn = (SSLConnection *)this->get_connection();
		conn->wrapper = SSLWrapper(msg, conn->ssl);
		return &conn->wrapper;
	}

	int init_ssl_connection();

	std::string proxy_auth_;
	ParsedURI user_uri_;
	bool is_ssl_;
	bool is_user_request_;
	short state_;
	int error_;
};

int ComplexHttpProxyTask::init_ssl_connection()
{
	SSL *ssl = __create_ssl(WFGlobal::get_ssl_client_ctx());
	WFConnection *conn;

	if (!ssl)
		return -1;

	SSL_set_tlsext_host_name(ssl, user_uri_.host);
	SSL_set_connect_state(ssl);

	conn = this->ComplexHttpTask::get_connection();
	SSLConnection *ssl_conn = new SSLConnection(ssl);

	auto&& deleter = [] (void *ctx)
	{
		SSLConnection *ssl_conn = (SSLConnection *)ctx;
		SSL_free(ssl_conn->ssl);
		delete ssl_conn;
	};
	conn->set_context(ssl_conn, std::move(deleter));
	return 0;
}

CommMessageOut *ComplexHttpProxyTask::message_out()
{
	long long seqid = this->get_seq();

	if (seqid == 0) // CONNECT
	{
		HttpRequest *conn_req = new HttpRequest;
		std::string request_uri(user_uri_.host);

		request_uri += ":";
		if (user_uri_.port)
			request_uri += user_uri_.port;
		else
			request_uri += is_ssl_ ? "443" : "80";

		conn_req->set_method("CONNECT");
		conn_req->set_request_uri(request_uri);
		conn_req->set_http_version("HTTP/1.1");
		conn_req->add_header_pair("Host", request_uri.c_str());

		if (!proxy_auth_.empty())
			conn_req->add_header_pair("Proxy-Authorization", proxy_auth_);

		is_user_request_ = false;
		return conn_req;
	}
	else if (seqid == 1 && is_ssl_) // HANDSHAKE
	{
		is_user_request_ = false;
		return get_ssl_handshaker();
	}

	auto *msg = (ProtocolMessage *)this->ComplexHttpTask::message_out();
	return is_ssl_ ? get_ssl_wrapper(msg) : msg;
}

CommMessageIn *ComplexHttpProxyTask::message_in()
{
	long long seqid = this->get_seq();

	if (seqid == 0)
	{
		HttpResponse *conn_resp = new HttpResponse;
		conn_resp->parse_zero_body();
		return conn_resp;
	}
	else if (seqid == 1 && is_ssl_)
		return get_ssl_handshaker();

	auto *msg = (ProtocolMessage *)this->ComplexHttpTask::message_in();
	return is_ssl_ ? get_ssl_wrapper(msg) : msg;
}

int ComplexHttpProxyTask::keep_alive_timeout()
{
	long long seqid = this->get_seq();

	state_ = WFT_STATE_SUCCESS;
	error_ = 0;
	if (seqid == 0)
	{
		HttpResponse *resp = this->get_resp();
		const char *code_str;
		int status_code;

		*resp = std::move(*(HttpResponse *)this->get_message_in());
		code_str = resp->get_status_code();
		status_code = code_str ? atoi(code_str) : 0;

		switch (status_code)
		{
		case 200:
			break;
		case 407:
			this->disable_retry();
		default:
			state_ = WFT_STATE_TASK_ERROR;
			error_ = WFT_ERR_HTTP_PROXY_CONNECT_FAILED;
			return 0;
		}

		this->clear_resp();

		if (is_ssl_ && init_ssl_connection() < 0)
		{
			state_ = WFT_STATE_SYS_ERROR;
			error_ = errno;
			return 0;
		}

		return HTTP_KEEPALIVE_DEFAULT;
	}
	else if (seqid == 1 && is_ssl_)
		return HTTP_KEEPALIVE_DEFAULT;

	return this->ComplexHttpTask::keep_alive_timeout();
}

bool ComplexHttpProxyTask::init_success()
{
	if (!uri_.scheme || strcasecmp(uri_.scheme, "http") != 0)
	{
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_URI_SCHEME_INVALID;
		return false;
	}

	if (user_uri_.state == URI_STATE_ERROR)
	{
		this->state = WFT_STATE_SYS_ERROR;
		this->error = uri_.error;
		return false;
	}
	else if (user_uri_.state != URI_STATE_SUCCESS)
	{
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_URI_PARSE_FAILED;
		return false;
	}

	if (user_uri_.scheme && strcasecmp(user_uri_.scheme, "http") == 0)
		is_ssl_ = false;
	else if (user_uri_.scheme && strcasecmp(user_uri_.scheme, "https") == 0)
		is_ssl_ = true;
	else
	{
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_URI_SCHEME_INVALID;
		this->set_empty_request();
		return false;
	}

	int user_port;
	if (user_uri_.port)
	{
		user_port = atoi(user_uri_.port);
		if (user_port <= 0 || user_port > 65535)
		{
			this->state = WFT_STATE_TASK_ERROR;
			this->error = WFT_ERR_URI_PORT_INVALID;
			return false;
		}
	}
	else
		user_port = is_ssl_ ? 443 : 80;

	if (uri_.userinfo && uri_.userinfo[0])
	{
		proxy_auth_.clear();
		if (__encode_auth(uri_.userinfo, proxy_auth_) < 0)
		{
			this->state = WFT_STATE_SYS_ERROR;
			this->error = errno;
			return false;
		}
	}

	std::string info("http-proxy|remote:");
	info += is_ssl_ ? "https://" : "http://";
	info += user_uri_.host;
	info += ":";
	if (user_uri_.port)
		info += user_uri_.port;
	else
		info += is_ssl_ ? "443" : "80";
	info += "|auth:";
	info += proxy_auth_;

	this->WFComplexClientTask::set_info(info);

	std::string request_uri;
	std::string header_host;

	if (user_uri_.path && user_uri_.path[0])
		request_uri = user_uri_.path;
	else
		request_uri = "/";

	if (user_uri_.query && user_uri_.query[0])
	{
		request_uri += "?";
		request_uri += user_uri_.query;
	}

	if (user_uri_.host && user_uri_.host[0])
		header_host = user_uri_.host;

	if ((is_ssl_ && user_port != 443) || (!is_ssl_ && user_port != 80))
	{
		header_host += ":";
		header_host += uri_.port;
	}

	HttpRequest *client_req = this->get_req();
	client_req->set_request_uri(request_uri.c_str());
	client_req->set_header_pair("Host", header_host.c_str());
	this->WFComplexClientTask::set_transport_type(TT_TCP);
	return true;
}

bool ComplexHttpProxyTask::finish_once()
{
	if (!is_user_request_)
	{
		if (this->state == WFT_STATE_SUCCESS && state_ != WFT_STATE_SUCCESS)
		{
			this->state = state_;
			this->error = error_;
		}

		if (this->get_seq() == 0)
		{
			delete this->get_message_in();
			delete this->get_message_out();
		}

		is_user_request_ = true;
		return false;
	}

	if (this->state != WFT_STATE_SUCCESS)
		this->check_response();

	if (this->state == WFT_STATE_SUCCESS)
	{
		if (this->need_redirect(user_uri_))
			this->set_redirect(uri_);
		else if (this->state != WFT_STATE_SUCCESS)
			this->disable_retry();
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

WFHttpTask *WFTaskFactory::create_http_task(const std::string& url,
											const std::string& proxy_url,
											int redirect_max,
											int retry_max,
											http_callback_t callback)
{
	auto *task = new ComplexHttpProxyTask(redirect_max,
										  retry_max,
										  std::move(callback));

	ParsedURI uri, user_uri;
	URIParser::parse(url, user_uri);
	URIParser::parse(proxy_url, uri);

	task->set_user_uri(std::move(user_uri));
	task->set_keep_alive(HTTP_KEEPALIVE_DEFAULT);
	task->init(std::move(uri));
	return task;
}

WFHttpTask *WFTaskFactory::create_http_task(const ParsedURI& uri,
											const ParsedURI& proxy_uri,
											int redirect_max,
											int retry_max,
											http_callback_t callback)
{
	auto *task = new ComplexHttpProxyTask(redirect_max,
										  retry_max,
										  std::move(callback));

	task->set_user_uri(uri);
	task->set_keep_alive(HTTP_KEEPALIVE_DEFAULT);
	task->init(proxy_uri);
	return task;
}

/**********Server**********/

void WFHttpServerTask::handle(int state, int error)
{
	if (state == WFT_STATE_TOREPLY)
	{
		req_is_alive_ = this->req.is_keep_alive();
		if (req_is_alive_ && this->req.has_keep_alive_header())
		{
			HttpHeaderCursor req_cursor(&this->req);
			struct HttpMessageHeader header;

			header.name = "Keep-Alive";
			header.name_len = strlen("Keep-Alive");
			req_has_keep_alive_header_ = req_cursor.find(&header);
			if (req_has_keep_alive_header_)
			{
				req_keep_alive_.assign((const char *)header.value,
										header.value_len);
			}
		}
	}

	this->WFServerTask::handle(state, error);
}

CommMessageOut *WFHttpServerTask::message_out()
{
	HttpResponse *resp = this->get_resp();
	struct HttpMessageHeader header;

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

	if (!resp->is_chunked() && !resp->has_content_length_header())
	{
		char buf[32];
		header.name = "Content-Length";
		header.name_len = strlen("Content-Length");
		header.value = buf;
		header.value_len = sprintf(buf, "%zu", resp->get_output_body_size());
		resp->add_header(&header);
	}

	bool is_alive;

	if (resp->has_connection_header())
		is_alive = resp->is_keep_alive();
	else
		is_alive = req_is_alive_;

	if (!is_alive)
		this->keep_alive_timeo = 0;
	else
	{
		//req---Connection: Keep-Alive
		//req---Keep-Alive: timeout=5,max=100

		if (req_has_keep_alive_header_)
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
					// keep_alive_timeo = 5000ms when Keep-Alive: timeout=5
					this->keep_alive_timeo = 1000 * atoi(val.c_str());
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

	if (!resp->has_connection_header())
	{
		header.name = "Connection";
		header.name_len = 10;
		if (this->keep_alive_timeo == 0)
		{
			header.value = "close";
			header.value_len = 5;
		}
		else
		{
			header.value = "Keep-Alive";
			header.value_len = 10;
		}

		resp->add_header(&header);
	}

	return this->WFServerTask::message_out();
}


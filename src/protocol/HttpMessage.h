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

  Author: Xie Han (xiehan@sogou-inc.com)
*/

#ifndef _HTTPMESSAGE_H_
#define _HTTPMESSAGE_H_

#include <string.h>
#include <utility>
#include <string>
#include "list.h"
#include "ProtocolMessage.h"
#include "http_parser.h"

/**
 * @file   HttpMessage.h
 * @brief  Http Protocol Interface
 */

namespace protocol
{

struct HttpMessageHeader
{
	const void *name;
	size_t name_len;
	const void *value;
	size_t value_len;
};

class HttpMessage : public ProtocolMessage
{
public:
	const char *get_http_version() const
	{
		return http_parser_get_version(this->parser);
	}

	bool set_http_version(const char *version)
	{
		return http_parser_set_version(version, this->parser) == 0;
	}

	bool is_chunked() const
	{
		return http_parser_chunked(this->parser);
	}

	bool is_keep_alive() const
	{
		return http_parser_keep_alive(this->parser);
	}

	bool add_header(const struct HttpMessageHeader *header)
	{
		return http_parser_add_header(header->name, header->name_len,
									  header->value, header->value_len,
									  this->parser) == 0;
	}

	bool add_header_pair(const char *name, const char *value)
	{
		return http_parser_add_header(name, strlen(name),
									  value, strlen(value),
									  this->parser) == 0;
	}

	bool set_header(const struct HttpMessageHeader *header)
	{
		return http_parser_set_header(header->name, header->name_len,
									  header->value, header->value_len,
									  this->parser) == 0;
	}

	bool set_header_pair(const char *name, const char *value)
	{
		return http_parser_set_header(name, strlen(name),
									  value, strlen(value),
									  this->parser) == 0;
	}

	bool get_parsed_body(const void **body, size_t *size) const
	{
		return http_parser_get_body(body, size, this->parser) == 0;
	}

	/* Output body is for sending. Want to transfer a message received, maybe:
	 * msg->get_parsed_body(&body, &size);
	 * msg->append_output_body_nocopy(body, size); */
	bool append_output_body(const void *buf, size_t size);

	bool append_output_body(const char *buf)
	{
		return this->append_output_body(buf, strlen(buf));
	}

	bool append_output_body_nocopy(const void *buf, size_t size);

	bool append_output_body_nocopy(const char *buf)
	{
		return this->append_output_body_nocopy(buf, strlen(buf));
	}

	size_t get_output_body_size() const
	{
		return this->output_body_size;
	}

	size_t get_output_body_blocks(const void *buf[], size_t size[],
								  size_t max) const;

	bool get_output_body_merged(void *buf, size_t *size) const;

	void clear_output_body();

	/* std::string interfaces */
public:
	bool get_http_version(std::string& version) const
	{
		const char *str = this->get_http_version();

		if (str)
		{
			version.assign(str);
			return true;
		}

		return false;
	}

	bool set_http_version(const std::string& version)
	{
		return this->set_http_version(version.c_str());
	}

	bool add_header_pair(const std::string& name, const std::string& value)
	{
		return http_parser_add_header(name.c_str(), name.size(),
									  value.c_str(), value.size(),
									  this->parser) == 0;
	}

	bool set_header_pair(const std::string& name, const std::string& value)
	{
		return http_parser_set_header(name.c_str(), name.size(),
									  value.c_str(), value.size(),
									  this->parser) == 0;
	}

	bool append_output_body(const std::string& buf)
	{
		return this->append_output_body(buf.c_str(), buf.size());
	}

	bool append_output_body_nocopy(const std::string& buf)
	{
		return this->append_output_body_nocopy(buf.c_str(), buf.size());
	}

	bool get_output_body_merged(std::string& body) const
	{
		size_t size = this->output_body_size;
		body.resize(size);
		return this->get_output_body_merged((void *)body.data(), &size);
	}

	/* for http task implementations. */
public:
	bool is_header_complete() const
	{
		return http_parser_header_complete(this->parser);
	}

	bool has_connection_header() const
	{
		return http_parser_has_connection(this->parser);
	}

	bool has_content_length_header() const
	{
		return http_parser_has_content_length(this->parser);
	}

	bool has_keep_alive_header() const
	{
		return http_parser_has_keep_alive(this->parser);
	}

	void end_parsing()
	{
		http_parser_close_message(this->parser);
	}

	/* for header cursor implementations. */
	const http_parser_t *get_parser() const
	{
		return this->parser;
	}

protected:
	virtual int encode(struct iovec vectors[], int max);
	virtual int append(const void *buf, size_t *size);

protected:
	http_parser_t *parser;
	size_t cur_size;

private:
	struct list_head *combine_from(struct list_head *pos, size_t size);

private:
	struct list_head output_body;
	size_t output_body_size;

public:
	HttpMessage(bool is_resp) : parser(new http_parser_t)
	{
		http_parser_init(is_resp, this->parser);
		INIT_LIST_HEAD(&this->output_body);
		this->output_body_size = 0;
		this->cur_size = 0;
	}

	virtual ~HttpMessage()
	{
		this->clear_output_body();
		if (this->parser)
		{
			http_parser_deinit(this->parser);
			delete this->parser;
		}
	}

public:
	HttpMessage(HttpMessage&& msg);
	HttpMessage& operator = (HttpMessage&& msg);
};

class HttpRequest : public HttpMessage
{
public:
	const char *get_method() const
	{
		return http_parser_get_method(this->parser);
	}

	const char *get_request_uri() const
	{
		return http_parser_get_uri(this->parser);
	}

	bool set_method(const char *method)
	{
		return http_parser_set_method(method, this->parser) == 0;
	}

	bool set_request_uri(const char *uri)
	{
		return http_parser_set_uri(uri, this->parser) == 0;
	}

	/* std::string interfaces */
public:
	bool get_method(std::string& method) const
	{
		const char *str = this->get_method();

		if (str)
		{
			method.assign(str);
			return true;
		}

		return false;
	}

	bool get_request_uri(std::string& uri) const
	{
		const char *str = this->get_request_uri();

		if (str)
		{
			uri.assign(str);
			return true;
		}

		return false;
	}

	bool set_method(const std::string& method)
	{
		return this->set_method(method.c_str());
	}

	bool set_request_uri(const std::string& uri)
	{
		return this->set_request_uri(uri.c_str());
	}

protected:
	virtual int append(const void *buf, size_t *size);

private:
	int handle_expect_continue();

public:
	HttpRequest() : HttpMessage(false) { }

public:
	HttpRequest(HttpRequest&& req) = default;
	HttpRequest& operator = (HttpRequest&& req) = default;
};

class HttpResponse : public HttpMessage
{
public:
	const char *get_status_code() const
	{
		return http_parser_get_code(this->parser);
	}

	const char *get_reason_phrase() const
	{
		return http_parser_get_phrase(this->parser);
	}

	bool set_status_code(const char *code)
	{
		return http_parser_set_code(code, this->parser) == 0;
	}

	bool set_reason_phrase(const char *phrase)
	{
		return http_parser_set_phrase(phrase, this->parser) == 0;
	}

	/* std::string interfaces */
public:
	bool get_status_code(std::string& code) const
	{
		const char *str = this->get_status_code();

		if (str)
		{
			code.assign(str);
			return true;
		}

		return false;
	}

	bool get_reason_phrase(std::string& phrase) const
	{
		const char *str = this->get_reason_phrase();

		if (str)
		{
			phrase.assign(str);
			return true;
		}

		return false;
	}

	bool set_status_code(const std::string& code)
	{
		return this->set_status_code(code.c_str());
	}

	bool set_reason_phrase(const std::string& phrase)
	{
		return this->set_reason_phrase(phrase.c_str());
	}

public:
	/* Tell the parser, it is a HEAD response. For implementations. */
	void parse_zero_body()
	{
		this->parser->transfer_length = 0;
	}

protected:
	virtual int append(const void *buf, size_t *size);

public:
	HttpResponse() : HttpMessage(true) { }

public:
	HttpResponse(HttpResponse&& resp) = default;
	HttpResponse& operator = (HttpResponse&& resp) = default;
};

}

#endif


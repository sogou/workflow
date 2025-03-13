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

  Authors: Xie Han (xiehan@sogou-inc.com)
           Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

#include <string>
#include <vector>
#include <algorithm>
#include "http_parser.h"
#include "HttpMessage.h"
#include "HttpUtil.h"

namespace protocol
{

HttpHeaderMap::HttpHeaderMap(const HttpMessage *message)
{
	http_header_cursor_t cursor;
	struct HttpMessageHeader header;

	http_header_cursor_init(&cursor, message->get_parser());
	while (http_header_cursor_next(&header.name, &header.name_len,
								   &header.value, &header.value_len,
								   &cursor) == 0)
	{
		std::string key((const char *)header.name, header.name_len);

		std::transform(key.begin(), key.end(), key.begin(), ::tolower);
		header_map_[key].emplace_back((const char *)header.value, header.value_len);
	}

	http_header_cursor_deinit(&cursor);
}

bool HttpHeaderMap::key_exists(std::string key)
{
	std::transform(key.begin(), key.end(), key.begin(), ::tolower);
	return header_map_.count(key) > 0;
}

std::string HttpHeaderMap::get(std::string key)
{
	std::transform(key.begin(), key.end(), key.begin(), ::tolower);
	const auto it = header_map_.find(key);

	if (it == header_map_.end() || it->second.empty())
		return std::string();

	return it->second[0];
}

bool HttpHeaderMap::get(std::string key, std::string& value)
{
	std::transform(key.begin(), key.end(), key.begin(), ::tolower);
	const auto it = header_map_.find(key);

	if (it == header_map_.end() || it->second.empty())
		return false;

	value = it->second[0];
	return true;
}

std::vector<std::string> HttpHeaderMap::get_strict(std::string key)
{
	std::transform(key.begin(), key.end(), key.begin(), ::tolower);
	return header_map_[key];
}

bool HttpHeaderMap::get_strict(std::string key, std::vector<std::string>& values)
{
	std::transform(key.begin(), key.end(), key.begin(), ::tolower);
	const auto it = header_map_.find(key);

	if (it == header_map_.end() || it->second.empty())
		return false;

	values = it->second;
	return true;
}

std::string HttpUtil::decode_chunked_body(const HttpMessage *msg)
{
	const void *body;
	size_t body_len;
	const void *chunk;
	size_t chunk_size;
	std::string decode_result;
	HttpChunkCursor cursor(msg);

	if (msg->get_parsed_body(&body, &body_len))
	{
		decode_result.reserve(body_len);
		while (cursor.next(&chunk, &chunk_size))
			decode_result.append((const char *)chunk, chunk_size);
	}

	return decode_result;
}

void HttpUtil::set_response_status(HttpResponse *resp, int status_code)
{
	char buf[32];
	sprintf(buf, "%d", status_code);
	resp->set_status_code(buf);

	switch (status_code)
	{
	case 100:
		resp->set_reason_phrase("Continue");
		break;

	case 101:
		resp->set_reason_phrase("Switching Protocols");
		break;

	case 102:
		resp->set_reason_phrase("Processing");
		break;

	case 200:
		resp->set_reason_phrase("OK");
		break;

	case 201:
		resp->set_reason_phrase("Created");
		break;

	case 202:
		resp->set_reason_phrase("Accepted");
		break;

	case 203:
		resp->set_reason_phrase("Non-Authoritative Information");
		break;

	case 204:
		resp->set_reason_phrase("No Content");
		break;

	case 205:
		resp->set_reason_phrase("Reset Content");
		break;

	case 206:
		resp->set_reason_phrase("Partial Content");
		break;

	case 207:
		resp->set_reason_phrase("Multi-Status");
		break;

	case 208:
		resp->set_reason_phrase("Already Reported");
		break;

	case 226:
		resp->set_reason_phrase("IM Used");
		break;

	case 300:
		resp->set_reason_phrase("Multiple Choices");
		break;

	case 301:
		resp->set_reason_phrase("Moved Permanently");
		break;

	case 302:
		resp->set_reason_phrase("Found");
		break;

	case 303:
		resp->set_reason_phrase("See Other");
		break;

	case 304:
		resp->set_reason_phrase("Not Modified");
		break;

	case 305:
		resp->set_reason_phrase("Use Proxy");
		break;

	case 306:
		resp->set_reason_phrase("Switch Proxy");
		break;

	case 307:
		resp->set_reason_phrase("Temporary Redirect");
		break;

	case 308:
		resp->set_reason_phrase("Permanent Redirect");
		break;

	case 400:
		resp->set_reason_phrase("Bad Request");
		break;

	case 401:
		resp->set_reason_phrase("Unauthorized");
		break;

	case 402:
		resp->set_reason_phrase("Payment Required");
		break;

	case 403:
		resp->set_reason_phrase("Forbidden");
		break;

	case 404:
		resp->set_reason_phrase("Not Found");
		break;

	case 405:
		resp->set_reason_phrase("Method Not Allowed");
		break;

	case 406:
		resp->set_reason_phrase("Not Acceptable");
		break;

	case 407:
		resp->set_reason_phrase("Proxy Authentication Required");
		break;

	case 408:
		resp->set_reason_phrase("Request Timeout");
		break;

	case 409:
		resp->set_reason_phrase("Conflict");
		break;

	case 410:
		resp->set_reason_phrase("Gone");
		break;

	case 411:
		resp->set_reason_phrase("Length Required");
		break;

	case 412:
		resp->set_reason_phrase("Precondition Failed");
		break;

	case 413:
		resp->set_reason_phrase("Request Entity Too Large");
		break;

	case 414:
		resp->set_reason_phrase("Request-URI Too Long");
		break;

	case 415:
		resp->set_reason_phrase("Unsupported Media Type");
		break;

	case 416:
		resp->set_reason_phrase("Requested Range Not Satisfiable");
		break;

	case 417:
		resp->set_reason_phrase("Expectation Failed");
		break;

	case 418:
		resp->set_reason_phrase("I'm a teapot");
		break;

	case 420:
		resp->set_reason_phrase("Enhance Your Caim");
		break;

	case 421:
		resp->set_reason_phrase("Misdirected Request");
		break;

	case 422:
		resp->set_reason_phrase("Unprocessable Entity");
		break;

	case 423:
		resp->set_reason_phrase("Locked");
		break;

	case 424:
		resp->set_reason_phrase("Failed Dependency");
		break;

	case 425:
		resp->set_reason_phrase("Too Early");
		break;

	case 426:
		resp->set_reason_phrase("Upgrade Required");
		break;

	case 428:
		resp->set_reason_phrase("Precondition Required");
		break;

	case 429:
		resp->set_reason_phrase("Too Many Requests");
		break;

	case 431:
		resp->set_reason_phrase("Request Header Fields Too Large");
		break;

	case 444:
		resp->set_reason_phrase("No Response");
		break;

	case 450:
		resp->set_reason_phrase("Blocked by Windows Parental Controls");
		break;

	case 451:
		resp->set_reason_phrase("Unavailable For Legal Reasons");
		break;

	case 494:
		resp->set_reason_phrase("Request Header Too Large");
		break;

	case 500:
		resp->set_reason_phrase("Internal Server Error");
		break;

	case 501:
		resp->set_reason_phrase("Not Implemented");
		break;

	case 502:
		resp->set_reason_phrase("Bad Gateway");
		break;

	case 503:
		resp->set_reason_phrase("Service Unavailable");
		break;

	case 504:
		resp->set_reason_phrase("Gateway Timeout");
		break;

	case 505:
		resp->set_reason_phrase("HTTP Version Not Supported");
		break;

	case 506:
		resp->set_reason_phrase("Variant Also Negotiates");
		break;

	case 507:
		resp->set_reason_phrase("Insufficient Storage");
		break;

	case 508:
		resp->set_reason_phrase("Loop Detected");
		break;

	case 510:
		resp->set_reason_phrase("Not Extended");
		break;

	case 511:
		resp->set_reason_phrase("Network Authentication Required");
		break;

	default:
		resp->set_reason_phrase("Unknown");
		break;
	}
}

bool HttpHeaderCursor::next(std::string& name, std::string& value)
{
	struct HttpMessageHeader header;

	if (this->next(&header))
	{
		name.assign((const char *)header.name, header.name_len);
		value.assign((const char *)header.value, header.value_len);
		return true;
	}

	return false;
}

bool HttpHeaderCursor::find(const std::string& name, std::string& value)
{
	struct HttpMessageHeader header = {
		.name		=	name.c_str(),
		.name_len	=	name.size(),
	};

	if (this->find(&header))
	{
		value.assign((const char *)header.value, header.value_len);
		return true;
	}

	return false;
}

bool HttpHeaderCursor::find_and_erase(const std::string& name)
{
	struct HttpMessageHeader header = {
		.name		=	name.c_str(),
		.name_len	=	name.size(),
	};
	return this->find_and_erase(&header);
}

HttpChunkCursor::HttpChunkCursor(const HttpMessage *msg)
{
	if (msg->get_parsed_body(&this->body, &this->body_len))
	{
		this->pos = this->body;
		this->chunked = msg->is_chunked();
		this->end = false;
	}
	else
	{
		this->body = NULL;
		this->end = true;
	}
}

bool HttpChunkCursor::next(const void **chunk, size_t *size)
{
	if (this->end)
		return false;

	if (!this->chunked)
	{
		*chunk = this->body;
		*size = this->body_len;
		this->end = true;
		return true;
	}

	const char *cur = (const char *)this->pos;
	char *end;

	*size = strtoul(cur, &end, 16);
	if (*size == 0)
	{
		this->end = true;
		return false;
	}

	cur = strchr(end, '\r');
	*chunk = cur + 2;
	cur += *size + 4;
	this->pos = cur;
	return true;
}

void HttpChunkCursor::rewind()
{
	if (this->body)
	{
		this->pos = this->body;
		this->end = false;
	}
}

}


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

#ifndef _ENCODESTREAM_H_
#define _ENCODESTREAM_H_

#include <sys/uio.h>
#include <stdint.h>
#include <string.h>
#include <string>
#include "list.h"

/**
 * @file   EncodeStream.h
 * @brief  Encoder toolbox for protocol message encode
 */

// make sure max > 0
class EncodeStream
{
public:
	EncodeStream()
	{
		init_vec(NULL, 0);
		INIT_LIST_HEAD(&buf_list_);
	}

	EncodeStream(struct iovec *vectors, int max)
	{
		init_vec(vectors, max);
		INIT_LIST_HEAD(&buf_list_);
	}

	~EncodeStream() { clear_buf_data(); }

	void reset(struct iovec *vectors, int max)
	{
		clear_buf_data();
		init_vec(vectors, max);
	}

	int size() const { return size_; }
	size_t bytes() const { return bytes_; }

	void append_nocopy(const char *data, size_t len);

	void append_nocopy(const char *data)
	{
		append_nocopy(data, strlen(data));
	}

	void append_nocopy(const std::string& data)
	{
		append_nocopy(data.c_str(), data.size());
	}

	void append_copy(const char *data, size_t len);

	void append_copy(const char *data)
	{
		append_copy(data, strlen(data));
	}

	void append_copy(const std::string& data)
	{
		append_copy(data.c_str(), data.size());
	}

private:
	void init_vec(struct iovec *vectors, int max)
	{
		vec_ = vectors;
		max_ = max;
		bytes_ = 0;
		size_ = 0;
		merged_bytes_ = 0;
		merged_size_ = 0;
	}

	void merge();
	void clear_buf_data();

private:
	struct iovec *vec_;
	int max_;
	int size_;
	size_t bytes_;
	int merged_size_;
	size_t merged_bytes_;
	struct list_head buf_list_;
};

static inline EncodeStream& operator << (EncodeStream& stream,
										 const char *data)
{
	stream.append_nocopy(data, strlen(data));
	return stream;
}

static inline EncodeStream& operator << (EncodeStream& stream,
										 const std::string& data)
{
	stream.append_nocopy(data.c_str(), data.size());
	return stream;
}

static inline EncodeStream& operator << (EncodeStream& stream,
								const std::pair<const char *, size_t>& data)
{
	stream.append_nocopy(data.first, data.second);
	return stream;
}

static inline EncodeStream& operator << (EncodeStream& stream,
										 int64_t intv)
{
	stream.append_copy(std::to_string(intv));
	return stream;
}

#endif


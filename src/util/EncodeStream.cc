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
*/

#include <sys/uio.h>
#include <stddef.h>
#include <string.h>
#include "list.h"
#include "EncodeStream.h"

#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))
#define ENCODE_BUF_SIZE		1024

struct EncodeBuf
{
	struct list_head list;
	char *pos;
	char data[ENCODE_BUF_SIZE];
};

void EncodeStream::clear_buf_data()
{
	struct list_head *pos, *tmp;
	struct EncodeBuf *entry;

	list_for_each_safe(pos, tmp, &buf_list_)
	{
		entry = list_entry(pos, struct EncodeBuf, list);
		list_del(pos);
		delete [](char *)entry;
	}
}

void EncodeStream::merge()
{
	size_t len = bytes_ - merged_bytes_;
	struct EncodeBuf *buf;
	size_t n;
	char *p;
	int i;

	if (len > ENCODE_BUF_SIZE)
		n = offsetof(struct EncodeBuf, data) + ALIGN(len, 8);
	else
		n = sizeof (struct EncodeBuf);

	buf = (struct EncodeBuf *)new char[n];
	p = buf->data;
	for (i = merged_size_; i < size_; i++)
	{
		memcpy(p, vec_[i].iov_base, vec_[i].iov_len);
		p += vec_[i].iov_len;
	}

	buf->pos = buf->data + ALIGN(len, 8);
	list_add(&buf->list, &buf_list_);

	vec_[merged_size_].iov_base = buf->data;
	vec_[merged_size_].iov_len = len;
	merged_size_++;
	merged_bytes_ = bytes_;
	size_ = merged_size_;
}

void EncodeStream::append_nocopy(const char *data, size_t len)
{
	if (size_ >= max_)
	{
		if (merged_size_ + 1 < max_)
			merge();
		else
		{
			size_ = max_ + 1;	/* Overflow */
			return;
		}
	}

	vec_[size_].iov_base = (char *)data;
	vec_[size_].iov_len = len;
	size_++;
	bytes_ += len;
}

void EncodeStream::append_copy(const char *data, size_t len)
{
	if (size_ >= max_)
	{
		if (merged_size_ + 1 < max_)
			merge();
		else
		{
			size_ = max_ + 1;	/* Overflow */
			return;
		}
	}

	struct EncodeBuf *buf = list_entry(buf_list_.prev, struct EncodeBuf, list);

	if (list_empty(&buf_list_) || buf->pos + len > buf->data + ENCODE_BUF_SIZE)
	{
		size_t n;

		if (len > ENCODE_BUF_SIZE)
			n = offsetof(struct EncodeBuf, data) + ALIGN(len, 8);
		else
			n = sizeof (struct EncodeBuf);

		buf = (struct EncodeBuf *)new char[n];
		buf->pos = buf->data;
		list_add_tail(&buf->list, &buf_list_);
	}

	memcpy(buf->pos, data, len);
	vec_[size_].iov_base = buf->pos;
	vec_[size_].iov_len = len;
	size_++;
	bytes_ += len;

	buf->pos += ALIGN(len, 8);
	if (buf->pos >= buf->data + ENCODE_BUF_SIZE)
		list_move(&buf->list, &buf_list_);
}


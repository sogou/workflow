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
*/

#include <stdio.h>
#include <string.h>
#include "list.h"
#include "EncodeStream.h"

struct __buff
{
	struct list_head buffer_list;
	const char *data;
	size_t len;
	std::string str;
};

void EncodeStream::clear_buffer()
{
	struct list_head *pos, *tmp;
	__buff *next;

	list_for_each_safe(pos, tmp, &buffer_list_)
	{
		next = list_entry(pos, __buff, buffer_list);
		list_del(pos);
		delete next;
	}
}

void EncodeStream::check_merge()
{
	if (size_ >= max_)
	{
		list_head *head = &buffer_list_;
		list_head *pos = head->next;
		list_head *next = pos->next;

		size_ = 0;
		while (pos != head && next != head)
		{
			__buff *x = list_entry(pos, __buff, buffer_list);
			__buff *y = list_entry(next, __buff, buffer_list);

			if (x->str.empty())
				x->str.assign(x->data, x->len);

			x->str.append(y->data, y->len);
			x->data = x->str.c_str();
			x->len = x->str.size();
			list_del(next);
			delete y;
			vec_[size_].iov_base = const_cast<char *>(x->data);
			vec_[size_++].iov_len = x->len;
			pos = pos->next;
			next = pos->next;
		}

		if (pos != head)
		{
			__buff *x = list_entry(pos, __buff, buffer_list);

			vec_[size_].iov_base = const_cast<char *>(x->data);
			vec_[size_++].iov_len = x->len;
		}
	}
}

void EncodeStream::append_copy(const char *data, size_t len)
{
	if (len)
	{
		__buff *p = new __buff();

		p->str.assign(data, len);
		p->data = p->str.c_str();
		p->len = len;
		list_add_tail(&p->buffer_list, &buffer_list_);
		vec_[size_].iov_base = const_cast<char *>(p->data);
		vec_[size_++].iov_len = len;
		check_merge();
		bytes_ += len;
	}
}

void EncodeStream::append_nocopy(const char *data, size_t len)
{
	if (len)
	{
		__buff *p = new __buff();

		p->str.clear();
		p->data = data;
		p->len = len;
		list_add_tail(&p->buffer_list, &buffer_list_);
		vec_[size_].iov_base = const_cast<char *>(data);
		vec_[size_++].iov_len = len;
		check_merge();
		bytes_ += len;
	}
}


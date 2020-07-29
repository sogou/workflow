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

  Author: Xie Han (xiehan@sogou-inc.com)
*/

#include <assert.h>
#include <utility>
#include <vector>
#include <type_traits>
#include "rbtree.h"
#include "list.h"

namespace algorithm
{

template<typename VAL>
struct __ReduceValue
{
	struct list_head list;
	VAL value;
	__ReduceValue(VAL&& val) : value(std::move(val)) { }
};

template<typename KEY, typename VAL>
struct __ReduceKey
{
	struct rb_node rb;
	KEY key;
	struct list_head value_list;
	size_t value_cnt;

	__ReduceKey(KEY&& k) : key(std::move(k))
	{
		INIT_LIST_HEAD(&this->value_list);
		this->value_cnt = 0;
	}

	void insert(VAL&& value)
	{
		__ReduceValue<VAL> *entry = new __ReduceValue<VAL>(std::move(value));
		list_add_tail(&entry->list, &this->value_list);
		this->value_cnt++;
	}

	~__ReduceKey()
	{
		struct list_head *pos, *tmp;
		list_for_each_safe(pos, tmp, &this->value_list)
			delete list_entry(pos, struct __ReduceValue<VAL>, list);
	}
};

template<typename VAL, bool = std::is_class<VAL>::value>
class __ReduceIterator;

#define __REDUCE_ITERATOR_HEAP_MAX		256

/* VAL is a class. VAL must have size() method. */
template<typename VAL>
class __ReduceIterator<VAL, true> : public ReduceIterator<VAL>
{
public:
	virtual const VAL *next();
	virtual size_t size() { return this->original_size; }

private:
	void reduce_begin() { this->original_size = this->heap_size; }

	void reduce_end(VAL&& value)
	{
		size_t n = this->original_size;

		assert(n != this->heap_size);
		while (--n != this->heap_size)
			delete this->heap[n];

		this->heap[n]->value = std::move(value);
		this->heap_insert(this->heap[n]);
	}

	size_t count() { return this->heap_size; }

	__ReduceValue<VAL> *value() { return this->heap[0]; }

private:
	void heapify(int top);
	void heap_insert(__ReduceValue<VAL> *data);

private:
	__ReduceValue<VAL> *heap[__REDUCE_ITERATOR_HEAP_MAX];
	int heap_size;
	int original_size;

private:
	__ReduceIterator(struct list_head *value_list, size_t *value_cnt);
	template<class, class> friend class Reducer;
};

template<typename VAL>
const VAL *__ReduceIterator<VAL, true>::next()
{
	__ReduceValue<VAL> *data = this->heap[0];

	if (this->heap_size == 0)
		return NULL;

	this->heap[0] = this->heap[--this->heap_size];
	this->heapify(0);
	this->heap[this->heap_size] = data;
	return &data->value;
}

template<typename VAL>
void __ReduceIterator<VAL, true>::heapify(int top)
{
	__ReduceValue<VAL> *data = this->heap[top];
	__ReduceValue<VAL> **child;
	int last = this->heap_size - 1;
	int i;

	while (i = 2 * top + 1, i < last)
	{
		child = &this->heap[i];
		if (child[0]->value.size() < data->value.size())
		{
			if (child[1]->value.size() < child[0]->value.size())
			{
				this->heap[top] = child[1];
				top = i + 1;
			}
			else
			{
				this->heap[top] = child[0];
				top = i;
			}
		}
		else
		{
			if (child[1]->value.size() < data->value.size())
			{
				this->heap[top] = child[1];
				top = i + 1;
			}
			else
			{
				this->heap[top] = data;
				return;
			}
		}
	}

	if (i == last)
	{
		child = &this->heap[i];
		if (child[0]->value.size() < data->value.size())
		{
			this->heap[top] = child[0];
			top = i;
		}
	}

	this->heap[top] = data;
}

template<typename VAL>
void __ReduceIterator<VAL, true>::heap_insert(__ReduceValue<VAL> *data)
{
	__ReduceValue<VAL> *parent;
	int i = this->heap_size;

	while (i > 0)
	{
		parent = this->heap[(i - 1) / 2];
		if (data->value.size() < parent->value.size())
		{
			this->heap[i] = parent;
			i = (i - 1) / 2;
		}
		else
			break;
	}

	this->heap[i] = data;
	this->heap_size++;
}

template<typename VAL>
__ReduceIterator<VAL, true>::__ReduceIterator(struct list_head *value_list,
											  size_t *value_cnt)
{
	struct list_head *pos, *tmp;
	int n = 0;

	list_for_each_safe(pos, tmp, value_list)
	{
		if (n == __REDUCE_ITERATOR_HEAP_MAX)
			break;

		list_del(pos);
		this->heap[n++] = list_entry(pos, __ReduceValue<VAL>, list);
	}

	this->heap_size = n;
	*value_cnt -= n;
	n /= 2;
	while (n > 0)
		this->heapify(--n);
}

#undef __REDUCE_ITERATOR_HEAP_MAX

/* VAL is not a class. */
template<typename VAL>
class __ReduceIterator<VAL, false> : public ReduceIterator<VAL>
{
public:
	virtual const VAL *next()
	{
		if (this->cursor->next == &this->value_list)
			return NULL;

		this->cursor = this->cursor->next;
		this->value_cnt--;
		return &list_entry(this->cursor, __ReduceValue<VAL>, list)->value;
	}

	virtual size_t size() { return this->original_size; }

private:
	void reduce_begin()
	{
		this->cursor = &this->value_list;
		this->original_size = this->value_cnt;
	}

	void reduce_end(VAL&& value);

	size_t count() { return this->value_cnt; }

	__ReduceValue<VAL> *value()
	{
		return list_entry(this->value_list.next, __ReduceValue<VAL>, list);
	}

private:
	struct list_head value_list;
	size_t value_cnt;
	size_t original_size;
	struct list_head *cursor;

private:
	__ReduceIterator(struct list_head *value_list, size_t *value_cnt)
	{
		INIT_LIST_HEAD(&this->value_list);
		list_splice_init(value_list, &this->value_list);
		this->value_cnt = *value_cnt;
		*value_cnt = 0;
	}

	template<class, class> friend class Reducer;
};

template<class VAL>
void __ReduceIterator<VAL, false>::reduce_end(VAL&& value)
{
	__ReduceValue<VAL> *entry;

	assert(this->cursor != &this->value_list);
	while (this->value_list.next != this->cursor)
	{
		entry = list_entry(this->value_list.next, __ReduceValue<VAL>, list);
		list_del(&entry->list);
		delete entry;
	}

	entry = list_entry(this->cursor, __ReduceValue<VAL>, list);
	entry->value = std::move(value);
	list_move_tail(&entry->list, &this->value_list);
	this->value_cnt++;
}

template<typename KEY, typename VAL>
void Reducer<KEY, VAL>::insert(KEY&& key, VAL&& value)
{
	struct rb_node **p = &this->key_tree.rb_node;
	struct rb_node *parent = NULL;
	__ReduceKey<KEY, VAL> *entry;

	while (*p)
	{
		parent = *p;
		using TYPE = __ReduceKey<KEY, VAL>;
		entry = rb_entry(*p, TYPE, rb);
		if (key < entry->key)
			p = &(*p)->rb_left;
		else if (key > entry->key)
			p = &(*p)->rb_right;
		else
			break;
	}

	if (!*p)
	{
		entry = new __ReduceKey<KEY, VAL>(std::move(key));
		rb_link_node(&entry->rb, parent, p);
		rb_insert_color(&entry->rb, &this->key_tree);
	}

	entry->insert(std::move(value));
}

template<typename KEY, typename VAL>
void Reducer<KEY, VAL>::start(reduce_function_t<KEY, VAL> reduce,
							  std::vector<std::pair<KEY, VAL>> *result)
{
	struct rb_node *p = rb_first(&this->key_tree);
	__ReduceKey<KEY, VAL> *key;
	__ReduceValue<VAL> *value;

	while (p)
	{
		using TYPE = __ReduceKey<KEY, VAL>;
		key = rb_entry(p, TYPE, rb);
		while (key->value_cnt > 1)
		{
			__ReduceIterator<VAL> iter(&key->value_list, &key->value_cnt);

			do
			{
				VAL tmp;
				iter.reduce_begin();
				reduce(&key->key, &iter, &tmp);
				iter.reduce_end(std::move(tmp));
			} while (iter.count() > 1);

			list_add_tail(&iter.value()->list, &key->value_list);
			key->value_cnt++;
		}

		value = list_entry(key->value_list.next, __ReduceValue<VAL>, list);
		list_del(&value->list);
		result->emplace_back(std::move(key->key), std::move(value->value));
		delete value;

		p = rb_next(p);
		rb_erase(&key->rb, &this->key_tree);
		delete key;
	}
}

template<typename KEY, typename VAL>
Reducer<KEY, VAL>::~Reducer()
{
	__ReduceKey<KEY, VAL> *entry;

	while (this->key_tree.rb_node)
	{
		using TYPE = __ReduceKey<KEY, VAL>;
		entry = rb_entry(this->key_tree.rb_node, TYPE, rb);
		rb_erase(&entry->rb, &this->key_tree);
		delete entry;
	}
}

}


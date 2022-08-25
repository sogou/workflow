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
           Xie Han (xiehan@sogou-inc.com)
*/

#ifndef _LRUCACHE_H_
#define _LRUCACHE_H_

#include <assert.h>
#include "list.h"
#include "rbtree.h"

/**
 * @file   LRUCache.h
 * @brief  Template LRU Cache
 */

// RAII: NO. Release ref by LRUCache::release
// Thread safety: NO.
// DONOT change value by handler, use Cache::put instead
template<typename KEY, typename VALUE>
class LRUHandle
{
public:
	VALUE value;

private:
	LRUHandle(const KEY& k, const VALUE& v) :
		value(v), key(k)
	{
	}

	KEY key;
	struct list_head list;
	struct rb_node rb;
	bool in_cache;
	int ref;

	template<typename, typename, class> friend class LRUCache;
};

// RAII: NO. Release ref by LRUCache::release
// Define ValueDeleter(VALUE& v) for value deleter
// Thread safety: NO
// Make sure KEY operator< usable
template<typename KEY, typename VALUE, class ValueDeleter>
class LRUCache
{
protected:
	typedef LRUHandle<KEY, VALUE>			Handle;

public:
	LRUCache()
	{
		INIT_LIST_HEAD(&this->not_use);
		INIT_LIST_HEAD(&this->in_use);
		this->cache_map.rb_node = NULL;
		this->max_size = 0;
		this->size = 0;
	}

	~LRUCache()
	{
		struct list_head *pos, *tmp;
		Handle *e;

		// Error if caller has an unreleased handle
		assert(list_empty(&this->in_use));
		list_for_each_safe(pos, tmp, &this->not_use)
		{
			e = list_entry(pos, Handle, list);
			assert(e->in_cache);
			e->in_cache = false;
			assert(e->ref == 1);// Invariant for not_use_ list.
			this->unref(e);
		}
	}

	// default max_size=0 means no-limit cache
	// max_size means max cache number of key-value pairs
	void set_max_size(size_t max_size)
	{
		this->max_size = max_size;
	}

	// Remove all cache that are not actively in use.
	void prune()
	{
		struct list_head *pos, *tmp;
		Handle *e;

		list_for_each_safe(pos, tmp, &this->not_use)
		{
			e = list_entry(pos, Handle, list);
			assert(e->ref == 1);
			rb_erase(&e->rb);
			this->erase_node(e);
		}
	}

	// release handle by get/put
	void release(const Handle *handle)
	{
		this->unref(const_cast<Handle *>(handle));
	}

	// get handler
	// Need call release when handle no longer needed
	const Handle *get(const KEY& key)
	{
		struct rb_node *p = this->cache_map.rb_node;
		Handle *bound = NULL;
		Handle *e;

		while (p)
		{
			e = rb_entry(p, Handle, rb);
			if (!(e->key < key))
			{
				bound = e;
				p = p->rb_left;
			}
			else
				p = p->rb_right;
		}

		if (bound && !(key < bound->key))
		{
			this->ref(bound);
			return bound;
		}

		return NULL;
	}

	// put copy
	// Need call release when handle no longer needed
	const Handle *put(const KEY& key, VALUE value)
	{
		struct rb_node **p = &this->cache_map.rb_node;
		struct rb_node *parent = NULL;
		Handle *bound = NULL;
		Handle *e;

		while (*p)
		{
			parent = *p;
			e = rb_entry(*p, Handle, rb);
			if (!(e->key < key))
			{
				bound = e;
				p = &(*p)->rb_left;
			}
			else
				p = &(*p)->rb_right;
		}

		e = new Handle(key, value);
		e->in_cache = true;
		e->ref = 2;
		list_add_tail(&e->list, &this->in_use);
		this->size++;

		if (bound && !(key < bound->key))
		{
			rb_replace_node(&bound->rb, &e->rb, &this->cache_map);
			this->erase_node(bound);
		}
		else
		{
			rb_link_node(&e->rb, parent, p);
			rb_insert_color(&e->rb, &this->cache_map);
		}

		if (this->max_size > 0)
		{
			while (this->size > this->max_size && !list_empty(&this->not_use))
			{
				Handle *tmp = list_entry(this->not_use.next, Handle, list);
				assert(tmp->ref == 1);
				rb_erase(&tmp->rb, &this->cache_map);
				this->erase_node(tmp);
			}
		}

		return e;
	}

	// delete from cache, deleter delay called when all inuse-handle release.
	void del(const KEY& key)
	{
		Handle *e = const_cast<Handle *>(this->get(key));

		if (e)
		{
			this->unref(e);
			rb_erase(&e->rb, &this->cache_map);
			this->erase_node(e);
		}
	}

private:
	void ref(Handle *e)
	{
		if (e->in_cache && e->ref == 1)
			list_move_tail(&e->list, &this->in_use);

		e->ref++;
	}

	void unref(Handle *e)
	{
		assert(e->ref > 0);
		if (--e->ref == 0)
		{
			assert(!e->in_cache);
			this->value_deleter(e->value);
			delete e;
		}
		else if (e->in_cache && e->ref == 1)
			list_move_tail(&e->list, &this->not_use);
	}

	void erase_node(Handle *e)
	{
		assert(e->in_cache);
		list_del(&e->list);
		e->in_cache = false;
		this->size--;
		this->unref(e);
	}

	size_t max_size;
	size_t size;

	struct list_head not_use;
	struct list_head in_use;
	struct rb_root cache_map;

	ValueDeleter value_deleter;
};

#endif


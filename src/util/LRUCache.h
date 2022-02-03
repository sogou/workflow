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

#ifndef _LRUCACHE_H_
#define _LRUCACHE_H_
#include <assert.h>
#include <map>
//#include <unordered_map>

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
	LRUHandle():
		prev(NULL),
		next(NULL),
		ref(0)
	{}

	LRUHandle(const KEY& k, const VALUE& v):
		value(v),
		key(k),
		prev(NULL),
		next(NULL),
		ref(0),
		in_cache(false)
	{}
	//ban copy constructor
	LRUHandle(const LRUHandle& copy);
	//ban copy operator
	LRUHandle& operator= (const LRUHandle& copy);
	//ban move constructor
	LRUHandle(LRUHandle&& move);
	//ban move operator
	LRUHandle& operator= (LRUHandle&& move);

	KEY key;
	LRUHandle *prev;
	LRUHandle *next;
	int ref;
	bool in_cache;

template<typename, typename, class> friend class LRUCache;
};

// RAII: NO. Release ref by LRUCache::release
// Define ValueDeleter(VALUE& v) for value deleter
// Thread safety: YES
// Make sure KEY operator< usable
template<typename KEY, typename VALUE, class ValueDeleter>
class LRUCache
{
protected:
//using Map = std::unordered_map<KEY, VALUE>;
//using Handle = LRUHandle<KEY, VALUE>;
//using Map = std::map<KEY, LRUHandle*>;
//using MapIterator = typename Map::iterator;
//using MapConstIterator = typename Map::const_iterator;
typedef LRUHandle<KEY, VALUE>			Handle;
typedef std::map<KEY, Handle*>			Map;
typedef typename Map::iterator			MapIterator;
typedef typename Map::const_iterator	MapConstIterator;

public:
	LRUCache():
		max_size_(0),
		size_(0)
	{
		not_use_.next = &not_use_;
		not_use_.prev = &not_use_;
		in_use_.next = &in_use_;
		in_use_.prev = &in_use_;
	}

	~LRUCache()
	{
		// Error if caller has an unreleased handle
		assert(in_use_.next == &in_use_);
		for (Handle *e = not_use_.next; e != &not_use_; )
		{
			Handle *next = e->next;

			assert(e->in_cache);
			e->in_cache = false;
			assert(e->ref == 1);// Invariant for not_use_ list.
			unref(e);
			e = next;
		}
	}

	// default max_size=0 means no-limit cache
	// max_size means max cache number of key-value pairs
	void set_max_size(size_t max_size)
	{
		max_size_ = max_size;
	}

	size_t get_max_size() const { return max_size_; }
	size_t size() const { return size_; }

	// Remove all cache that are not actively in use.
	void prune()
	{
		while (not_use_.next != &not_use_)
		{
			Handle *e = not_use_.next;

			assert(e->ref == 1);
			cache_map_.erase(e->key);
			erase_node(e);
		}
	}

	// release handle by get/put
	void release(Handle *handle)
	{
		unref(handle);
	}

	void release(const Handle *handle)
	{
		release(const_cast<Handle *>(handle));
	}

	// get handler
	// Need call release when handle no longer needed
	const Handle *get(const KEY& key)
	{
		MapConstIterator it = cache_map_.find(key);

		if (it != cache_map_.end())
		{
			ref(it->second);
			return it->second;
		}

		return NULL;
	}

	// put copy
	// Need call release when handle no longer needed
	const Handle *put(const KEY& key, VALUE value)
	{
		Handle *e = new Handle(key, value);

		e->ref = 1;
		size_++;
		e->in_cache = true;
		e->ref++;
		list_append(&in_use_, e);
		MapIterator it = cache_map_.find(key);
		if (it != cache_map_.end())
		{
			erase_node(it->second);
			it->second = e;
		}
		else
			cache_map_[key] = e;

		if (max_size_ > 0)
		{
			while (size_ > max_size_ && not_use_.next != &not_use_)
			{
				Handle *old = not_use_.next;

				assert(old->ref == 1);
				cache_map_.erase(old->key);
				erase_node(old);
			}
		}

		return e;
	}

	// delete from cache, deleter delay called when all inuse-handle release.
	void del(const KEY& key)
	{
		MapConstIterator it = cache_map_.find(key);

		if (it != cache_map_.end())
		{
			Handle *node = it->second;

			cache_map_.erase(it);
			erase_node(node);
		}
	}

private:
	void list_remove(Handle *node)
	{
		node->next->prev = node->prev;
		node->prev->next = node->next;
	}

	void list_append(Handle *list, Handle *node)
	{
		node->next = list;
		node->prev = list->prev;
		node->prev->next = node;
		node->next->prev = node;
	}

	void ref(Handle *e)
	{
		if (e->in_cache && e->ref == 1)
		{
			list_remove(e);
			list_append(&in_use_, e);
		}

		e->ref++;
	}

	void unref(Handle *e)
	{
		assert(e->ref > 0);
		e->ref--;
		if (e->ref == 0)
		{
			assert(!e->in_cache);
			value_deleter_(e->value);
			delete e;
		}
		else if (e->in_cache && e->ref == 1)
		{
			list_remove(e);
			list_append(&not_use_, e);
		}
	}

	void erase_node(Handle *e)
	{
		assert(e->in_cache);
		list_remove(e);
		e->in_cache = false;
		size_--;
		unref(e);
	}

	size_t max_size_;
	size_t size_;

	Handle not_use_;
	Handle in_use_;
	Map cache_map_;

	ValueDeleter value_deleter_;
};

#endif  // SSS_LRUCACHE_H_


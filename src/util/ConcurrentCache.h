/*
  Copyright (c) 2025 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#ifndef _CONCURRENTCACHE_H_
#define _CONCURRENTCACHE_H_

#include <mutex>
#include <functional>

/**
 * @file   ConcurrentCache.h
 * @brief  Thread-safe Wrapper for Cache Policy (LRU/LFU)
 */

template<typename KEY, typename VALUE, class Policy>
class ConcurrentCache
{
public:
    using Handle = typename Policy::Handle;

    ConcurrentCache(size_t max_size = 0)
    {
        size_t per_shard_max = 0;
        if (max_size > 0)
        {
            per_shard_max = max_size / SHARD_COUNT;
            if (per_shard_max == 0)
                per_shard_max = 1;
        }

        for (int i = 0; i < SHARD_COUNT; ++i)
        {
            this->shards_[i] = new Policy();
            if (max_size > 0)
                this->shards_[i]->set_max_size(per_shard_max);
        }
    }

    ~ConcurrentCache()
    {
        for (int i = 0; i < SHARD_COUNT; ++i)
            delete this->shards_[i];
    }

    const Handle *get(const KEY& key)
    {
        int idx = this->hash_func(key) % SHARD_COUNT;
        std::lock_guard<std::mutex> lock(this->locks_[idx]);
        return this->shards_[idx]->get(key);
    }

    const Handle *put(const KEY& key, VALUE value)
    {
        int idx = this->hash_func(key) % SHARD_COUNT;
        std::lock_guard<std::mutex> lock(this->locks_[idx]);
        return this->shards_[idx]->put(key, value);
    }

    void del(const KEY& key)
    {
        int idx = this->hash_func(key) % SHARD_COUNT;
        std::lock_guard<std::mutex> lock(this->locks_[idx]);
        this->shards_[idx]->del(key);
    }

    void release(const Handle *handle)
    {
        if (!handle) return;
        int idx = this->hash_func(handle->get_key()) % SHARD_COUNT;
        std::lock_guard<std::mutex> lock(this->locks_[idx]);
        this->shards_[idx]->release(handle);
    }

private:
    static const int SHARD_COUNT = 16;
    Policy *shards_[SHARD_COUNT];
    std::mutex locks_[SHARD_COUNT];
    std::hash<KEY> hash_func;
};

#endif
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

#ifndef _LFUCACHE_H_
#define _LFUCACHE_H_

#include <assert.h>
#include <stdint.h>
#include "list.h"
#include "rbtree.h"

/**
 * @file   LFUCache.h
 * @brief  Template LFU Cache (Least Frequently Used)
 */

template<typename KEY, typename VALUE>
class LFUHandle
{
public:
    VALUE value;
    const KEY& get_key() const { return this->key; }

private:
    LFUHandle(const KEY& k, const VALUE& v, uint64_t seq) :
        value(v), key(k), frequency(1), sequence(seq)
    {
    }

    KEY key;
    uint64_t frequency;
    uint64_t sequence;

    struct list_head list;
    struct rb_node rb_key;
    struct rb_node rb_freq;
    
    bool in_cache;
    int ref;

    template<typename, typename, class> friend class LFUCache;
};

template<typename KEY, typename VALUE, class ValueDeleter>
class LFUCache
{
public:
    typedef LFUHandle<KEY, VALUE> Handle;

    LFUCache()
    {
        INIT_LIST_HEAD(&this->not_use);
        INIT_LIST_HEAD(&this->in_use);
        this->key_root.rb_node = NULL;
        this->freq_root.rb_node = NULL;
        this->max_size = 0;
        this->size = 0;
        this->global_seq = 0;
    }

    ~LFUCache()
    {
        struct list_head *pos, *tmp;
        Handle *e;

        assert(list_empty(&this->in_use));
        list_for_each_safe(pos, tmp, &this->not_use)
        {
            e = list_entry(pos, Handle, list);
            assert(e->in_cache);
            e->in_cache = false;
            assert(e->ref == 1);
            this->unref(e);
        }
    }

    void set_max_size(size_t max_size)
    {
        this->max_size = max_size;
    }

    void release(const Handle *handle)
    {
        this->unref(const_cast<Handle *>(handle));
    }

    const Handle *get(const KEY& key)
    {
        Handle *e = this->find_by_key(key);
        if (e)
        {
            this->ref(e);
            this->touch(e);
            return e;
        }
        return NULL;
    }

    const Handle *put(const KEY& key, VALUE value)
    {
        Handle *e = this->find_by_key(key);
        if (e)
        {
            this->value_deleter(e->value);
            e->value = value;
            this->touch(e);
            this->ref(e);
            return e;
        }

        e = new Handle(key, value, ++this->global_seq);
        e->in_cache = true;
        e->ref = 2; 
        
        this->insert_key_node(e);
        this->insert_freq_node(e);
        
        list_add_tail(&e->list, &this->in_use);
        this->size++;

        if (this->max_size > 0 && this->size > this->max_size)
            this->evict();

        return e;
    }

    void del(const KEY& key)
    {
        Handle *e = this->find_by_key(key);
        if (e)
            this->erase_node(e);
    }

private:
    Handle *find_by_key(const KEY& key)
    {
        struct rb_node *p = this->key_root.rb_node;
        Handle *e;

        while (p)
        {
            e = rb_entry(p, Handle, rb_key);
            if (key < e->key)
                p = p->rb_left;
            else if (e->key < key)
                p = p->rb_right;
            else
                return e;
        }
        return NULL;
    }

    void insert_key_node(Handle *e)
    {
        struct rb_node **p = &this->key_root.rb_node;
        struct rb_node *parent = NULL;
        Handle *tmp;

        while (*p)
        {
            parent = *p;
            tmp = rb_entry(*p, Handle, rb_key);
            if (e->key < tmp->key)
                p = &(*p)->rb_left;
            else
                p = &(*p)->rb_right;
        }
        rb_link_node(&e->rb_key, parent, p);
        rb_insert_color(&e->rb_key, &this->key_root);
    }

    void insert_freq_node(Handle *e)
    {
        struct rb_node **p = &this->freq_root.rb_node;
        struct rb_node *parent = NULL;
        Handle *tmp;

        while (*p)
        {
            parent = *p;
            tmp = rb_entry(*p, Handle, rb_freq);
            
            bool smaller = false;
            if (e->frequency < tmp->frequency)
                smaller = true;
            else if (e->frequency == tmp->frequency && e->sequence < tmp->sequence)
                smaller = true;

            if (smaller)
                p = &(*p)->rb_left;
            else
                p = &(*p)->rb_right;
        }
        rb_link_node(&e->rb_freq, parent, p);
        rb_insert_color(&e->rb_freq, &this->freq_root);
    }

    void touch(Handle *e)
    {
        rb_erase(&e->rb_freq, &this->freq_root);
        e->frequency++;
        e->sequence = ++this->global_seq;
        this->insert_freq_node(e);
    }

    void evict()
    {
        struct rb_node *node = rb_first(&this->freq_root);
        if (node)
        {
            Handle *e = rb_entry(node, Handle, rb_freq);
            this->erase_node(e);
        }
    }

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
        rb_erase(&e->rb_key, &this->key_root);
        rb_erase(&e->rb_freq, &this->freq_root);
        list_del(&e->list);
        e->in_cache = false;
        this->size--;
        this->unref(e); 
    }

    size_t max_size;
    size_t size;
    uint64_t global_seq;

    struct list_head not_use; 
    struct list_head in_use;  
    struct rb_root key_root;  
    struct rb_root freq_root; 

    ValueDeleter value_deleter;
};

#endif
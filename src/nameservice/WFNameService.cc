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

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "rbtree.h"
#include "WFNameService.h"

struct WFNSPolicyEntry
{
	struct rb_node rb;
	WFNSPolicy *policy;
	char name[1];
};

int WFNameService::add_policy(const char *name, WFNSPolicy *policy)
{
	struct rb_node **p = &this->root.rb_node;
	struct rb_node *parent = NULL;
	struct WFNSPolicyEntry *entry;
	int n, ret = -1;

	pthread_rwlock_wrlock(&this->rwlock);
	while (*p)
	{
		parent = *p;
		entry = rb_entry(*p, struct WFNSPolicyEntry, rb);
		n = strcasecmp(name, entry->name);
		if (n < 0)
			p = &(*p)->rb_left;
		else if (n > 0)
			p = &(*p)->rb_right;
		else
			break;
	}

	if (!*p)
	{
		size_t len = strlen(name);
		size_t size = offsetof(struct WFNSPolicyEntry, name) + len + 1;

		entry = (struct WFNSPolicyEntry *)malloc(size);
		if (entry)
		{
			memcpy(entry->name, name, len + 1);
			entry->policy = policy;
			rb_link_node(&entry->rb, parent, p);
			rb_insert_color(&entry->rb, &this->root);
			ret = 0;
		}
	}
	else
		errno = EEXIST;

	pthread_rwlock_unlock(&this->rwlock);
	return ret;
}

inline struct WFNSPolicyEntry *WFNameService::get_policy_entry(const char *name)
{
	struct rb_node *p = this->root.rb_node;
	struct WFNSPolicyEntry *entry;
	int n;

	while (p)
	{
		entry = rb_entry(p, struct WFNSPolicyEntry, rb);
		n = strcasecmp(name, entry->name);
		if (n < 0)
			p = p->rb_left;
		else if (n > 0)
			p = p->rb_right;
		else
			return entry;
	}

	return NULL;
}

WFNSPolicy *WFNameService::get_policy(const char *name)
{
	WFNSPolicy *policy = this->default_policy;
	struct WFNSPolicyEntry *entry;

	if (this->root.rb_node)
	{
		pthread_rwlock_rdlock(&this->rwlock);
		entry = this->get_policy_entry(name);
		if (entry)
			policy = entry->policy;

		pthread_rwlock_unlock(&this->rwlock);
	}

	return policy;
}

WFNSPolicy *WFNameService::del_policy(const char *name)
{
	WFNSPolicy *policy = NULL;
	struct WFNSPolicyEntry *entry;

	pthread_rwlock_wrlock(&this->rwlock);
	entry = this->get_policy_entry(name);
	if (entry)
	{
		policy = entry->policy;
		rb_erase(&entry->rb, &this->root);
	}

	pthread_rwlock_unlock(&this->rwlock);
	free(entry);
	return policy;
}

WFNameService::~WFNameService()
{
	struct WFNSPolicyEntry *entry;

	while (this->root.rb_node)
	{
		entry = rb_entry(this->root.rb_node, struct WFNSPolicyEntry, rb);
		rb_erase(&entry->rb, &this->root);
		free(entry);
	}
}


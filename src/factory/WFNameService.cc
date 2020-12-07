#include <errno.h>
#include <stddef.h>
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

struct WFNSPolicyEntry *WFNameService::get_policy_entry(const char *name)
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
	struct WFNSPolicyEntry *entry;

	pthread_rwlock_rdlock(&this->rwlock);
	entry = this->get_policy_entry(name);
	pthread_rwlock_unlock(&this->rwlock);

	return entry ? entry->policy : this->default_policy;
}

WFNSPolicy *WFNameService::del_policy(const char *name)
{
	struct WFNSPolicyEntry *entry;
	WFNSPolicy *policy;

	pthread_rwlock_wrlock(&this->rwlock);
	entry = this->get_policy_entry(name);
	if (entry)
		rb_erase(&entry->rb, &this->root);

	pthread_rwlock_unlock(&this->rwlock);
	if (entry)
	{
		policy = entry->policy;
		free(entry);
	}
	else
	{
		policy = NULL;
		errno = ENOENT;
	}

	return policy;
}


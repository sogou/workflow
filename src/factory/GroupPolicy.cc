#include "GovernancePolicy.h"

#define VIRTUAL_GROUP_SIZE	16

GroupPolicy::GroupPolicy()
{
	this->group_map.rb_node = NULL;
	this->default_group = new EndpointGroup(-1, this);
	rb_link_node(&this->default_group->rb, NULL, &this->group_map.rb_node);
	rb_insert_color(&this->default_group->rb, &this->group_map);
}

GroupPolicy::~GroupPolicy()
{
    EndpointGroup *group;

    while (this->group_map.rb_node)
    {    
        group = rb_entry(this->group_map.rb_node, EndpointGroup, rb);
        rb_erase(this->group.rb_node, &this->group_map);
        delete group;
    }
}

bool GroupPolicy::select(const ParsedURI& uri, EndpointAddress *addr)
{
	pthread_rwlock_rdlock(&this->rwlock);
	unsigned int n = (unsigned int)this->servers.size();

	if (n == 0)
	{
		pthread_rwlock_unlock(&this->rwlock);
		return false;
	}

	this->check_breaker();
	if (this->nalives == 0)
	{
		pthread_rwlock_unlock(&this->rwlock);
		return false;
	}

	// select_addr == NULL will only happened in consistent_hash
	const EndpointAddress *select_addr = this->first_stradegy(uri);

	if (!select_addr || select_addr->fail_count >= select_addr->params.max_fails)
	{
		if (select_addr)
			select_addr = addr->group->get_one();

		if (!select_addr && this->try_another)
			select_addr = this->another_stradegy();
	}

	if (!select_addr)
		this->default_group->get_one_backup();
	
	pthread_rwlock_unlock(&this->rwlock);

	if (select_addr)
	{
		*addr = (EndpointAddress *)select_addr;
		return true;
	}

	return false;
}

const EndpointAddress *EndpointGroup::get_one()
{
	if (this->nalives == 0)
		return NULL;

	const EndpointAddress *addr = NULL;
	pthread_mutex_lock(&this->mutex);

	std::random_shuffle(this->mains.begin(), this->mains.end());
	for (size_t i = 0; i < this->mains.size(); i++)
	{
		if (this->mains[i]->fail_count < this->mains[i]->params.max_fails)
		{
			addr = this->mains[i];
			break;
		}
	}

	if (!addr)
	{
		std::random_shuffle(this->backups.begin(), this->backups.end());
		for (size_t i = 0; i < this->backups.size(); i++)
		{
			if (this->backups[i]->fail_count < this->backups[i]->params.max_fails)
			{
				addr = this->backups[i];
				break;
			}
		}
	}

	pthread_mutex_unlock(&this->mutex);
	return addr;
}

const EndpointAddress *EndpointGroup::get_one_backup()
{
	if (this->nalives == 0)
		return NULL;

	const EndpointAddress *addr = NULL;
	pthread_mutex_lock(&this->mutex);

	std::random_shuffle(this->backups.begin(), this->backups.end());
	for (size_t i = 0; i < this->backups.size(); i++)
	{
		if (this->backups[i]->fail_count < this->backups[i]->params.max_fails)
		{
			addr = this->backups[i];
			break;
		}
	}

	pthread_mutex_unlock(&this->mutex);
	return addr;
}

void GroupPolicy::add_server(const std::string& address,
							 const AddressParams *address_params)
{
	auto *addr = new EndpointAddress(address, address_params);
	int group_id = addr->group_id;
	rb_node **p = &this->group_map.rb_node;
	rb_node *parent = NULL;
	EndpointGroup *group;

	pthread_rwlock_wrlock(&this->rwlock);
	this->addresses.push_back(addr);
	this->server_map[addr->address].push_back(addr);

	while (*p)
	{
		parent = *p;
		group = rb_entry(*p, EndpointGroup, rb);

		if (group_id < group->id)
			p = &(*p)->rb_left;
		else if (group_id > group->id)
			p = &(*p)->rb_right;
		else
			break;
	}

	if (*p == NULL)
	{
		group = new EndpointGroup(group_id, this);
		rb_link_node(&group->rb, parent, p);
		rb_insert_color(&group->rb, &this->group_map);
	}

	group->mutex.lock();
	this->recover_one_server();
	addr->group = group;
	if (addr->params.server_type == 0)
	{
		group->mains.push_back(addr);
		group->weight += addr->params.weight; // TODO
	}
	else
		group->backups.push_back(addr);
	group->mutex.unlock();

	pthread_rwlock_unlock(&this->rwlock);
	return;
}

int GroupPolicy::remove_server(const std::string& address)
{
	pthread_rwlock_rdlock(&this->rwlock);
	const auto map_it = this->server_map.find(address);

	if (map_it != this->server_map.cend())
	{
		for (EndpointAddress *addr : map_it->second)
		{
			EndpointGroup *group = addr->group;
			std::vector<EndpointAddress *> *vec;

			if (addr->params->server_type == 0)
				vec = &group->mains;
			else
				vec = &group->backups;

			std::lock_guard<std::mutex> lock(group->mutex);
			if (addr->fail_count < addr->params.max_fails)
				this->fuse_one_server(addr);

			if (addr->params->server_type == 0)
				group->weight -= ua->params.weight; // TODO

			for (auto it = vec->begin(); it != vec->end(); ++it)
			{
				if (*it == addr)
				{
					vec->erase(it);
					break;
				}
			}
		}

		this->server_map.erase(map_it);
	}

	size_t n = this->servers.size();
	size_t new_n = 0;

	for (size_t i = 0; i < n; i++)
	{
		if (this->servers[i]->address != address)
		{
			if (new_n != i)
				this->servers[new_n++] = this->servers[i];
			else
				new_n++;
		}
	}

	int ret = 0;
	if (new_n < n)
	{
		this->servers.resize(new_n);
		ret = n - new_n;
	}

	pthread_rwlock_unlock(&this->rwlock);
	return ret;
}

const EndpointAddress *GroupPolicy::consistent_hash_with_group(unsigned int hash) const
{
	const EndpointAddress *addr = NULL;
	unsigned int min_dis = (unsigned int)-1;

	for (const EndpointAddress *server : this->servers)
	{
		if (this->is_alive_or_group_alive(server))
		{
			for (int i = 0; i < VIRTUAL_GROUP_SIZE; i++)
			{
				unsigned int dis = std::min<unsigned int>
										   (hash - main->consistent_hash[i],
											main->consistent_hash[i] - hash);

				if (dis < min_dis)
				{
					min_dis = dis;
					addr = server;
				}
			}
		}
	}

	return this->check_and_get(addr);
}


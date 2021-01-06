#include "GovernancePolicy.h"
#include "StringUtil.h"

EndpointAddress::EndpointAddress(const std::string& address,
								 const struct AddressParams *address_params)
{
	std::vector<std::string> arr = StringUtil::split(address, ':');
	this->params = *address_params;
	this->address = address;

	if (this->params.weight == 0)
		this->params.weight = 1;

	if (this->params.max_fails == 0)
		this->params.max_fails = 1;

	if (this->params.group_id < 0)
		this->params.group_id = -1;

	if (arr.size() == 0)
		this->host = "";
	else
		this->host = arr[0];

	if (arr.size() <= 1)
	{
		this->port = "";
		this->port_value = 0;
	}
	else
	{
		this->port = arr[1];
		this->port_value = atoi(arr[1].c_str());
	}
}

void GovernancePolicy::success(RouteManager::RouteResult *result, void *cookie,
					 		   CommTarget *target)
{
	EndpointAddress *server = (EndpointAddress *)cookie;

	pthread_rwlock_rdlock(&this->rwlock);
	server->fail_count = 0;
	this->breaker_lock.lock();
	if (server->list.next)
	{
		list_del(&server->list);
		server->list.next = NULL;
		this->recover_server(server);
		//this->server_list_change();
	}
	this->breaker_lock.unlock();
	pthread_rwlock_unlock(&this->rwlock);

	WFDNSResolver::success(result, NULL, target);
}

void GovernancePolicy::failed(RouteManager::RouteResult *result, void *cookie,
							  CommTarget *target)
{
	EndpointAddress *server = (EndpointAddress *)cookie;

	pthread_rwlock_rdlock(&this->rwlock);
	int fail_count = ++server->fail_count;
	if (fail_count == server->params.max_fails)
	{
		this->breaker_lock.lock();
		if (!server->list.next)
		{
			server->broken_timeout = GET_CURRENT_SECOND + MTTR_SECOND;
			list_add_tail(&server->list, &this->breaker_list);
			this->fuse_server(server);
			//this->server_list_change();
		}
		this->breaker_lock.unlock();
	}
	pthread_rwlock_unlock(&this->rwlock);

	WFDNSResolver::failed(result, NULL, target);
}

void GovernancePolicy::recover_server(const EndpointAddress *addr)
{
	this->nalive++;
}

void GovernancePolicy::fuse_server(const EndpointAddress *addr)
{
	this->nalive--;
}

void GovernancePolicy::recover_breaker()
{
	this->breaker_lock.lock();
	if (!list_empty(&this->breaker_list))
	{
		int64_t cur_time = GET_CURRENT_SECOND;
		struct list_head *pos, *tmp;
		EndpointAddress *addr;

		list_for_each_safe(pos, tmp, &this->breaker_list)
		{
			addr = list_entry(pos, EndpointAddress, list);
			if (cur_time >= addr->broken_timeout)
			{
				if (addr->fail_count >= addr->params.max_fails)
				{
					addr->fail_count = addr->params.max_fails - 1;
					this->nalive++;
				}
				list_del(pos);
				addr->list.next = NULL;
			}
		}
	}
	this->breaker_lock.unlock();
	
	//this->server_list_change();
}

const EndpointAddress *GovernancePolicy::first_stradegy(const ParsedURI& uri)
{
	unsigned int idx = rand() % this->servers.size();
	return this->servers[idx];
}

const EndpointAddress *GovernancePolicy::another_stradegy(const ParsedURI& uri)
{
	return this->first_stradegy(uri);
}

bool GovernancePolicy::select(const ParsedURI& uri, EndpointAddress **addr)
{
	pthread_rwlock_rdlock(&this->rwlock);
	unsigned int n = (unsigned int)this->servers.size();

	if (n == 0)
	{
		pthread_rwlock_unlock(&this->rwlock);
		return false;
	}

	this->recover_breaker();
	if (this->nalive == 0)
	{
		pthread_rwlock_unlock(&this->rwlock);
		return false;
	}

	// select_addr == NULL will only happened in consistent_hash
	const EndpointAddress *select_addr = this->first_stradegy(uri);

	if (!select_addr || select_addr->fail_count >= select_addr->params.max_fails)
	{
		if (this->try_another)
			select_addr = this->another_stradegy(uri);
	}

	pthread_rwlock_unlock(&this->rwlock);

	if (select_addr)
	{
		*addr = (EndpointAddress *)select_addr;
		return true;
	}

	return false;
}

void GovernancePolicy::add_server(const std::string& address,
								  const AddressParams *address_params)
{
	auto *addr = new EndpointAddress(address, address_params);

	pthread_rwlock_wrlock(&this->rwlock);
	this->addresses.push_back(addr);
	this->server_map[addr->address].push_back(addr);
	this->servers.push_back(addr);
	this->nalive++;
	pthread_rwlock_unlock(&this->rwlock);
}

int GovernancePolicy::remove_server(const std::string& address)
{
	pthread_rwlock_wrlock(&this->rwlock);
	const auto map_it = this->server_map.find(address);
	if (map_it != this->server_map.cend())
	{
		for (auto addr : map_it->second)
		{
			if (addr->fail_count < addr->params.max_fails) // or not: it has already been -- in nalive
				this->nalive--;
		}

		this->server_map.erase(map_it);
	}

	int n = this->servers.size();
	int new_n = 0;

	for (int i = 0; i < n; i++)
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

void GovernancePolicy::enable_server(const std::string& address)
{
}

void GovernancePolicy::disable_server(const std::string& address)
{
}

/*
void GroupPolicy::recover_breaker()
{
	// recover every group in this policy
}

bool GroupPolicy::select(const ParsedURI& uri, EndpointAddress *addr)
{
	pthread_rwlock_rdlock(&this->rwlock);
	unsigned int n = (unsigned int)this->servers.size();

	if (n == 0)
		return false;

	if (n == 1)
	{
		addr = this->servers[0];
		return true;
	}

	this->recover_breaker();

	// select_addr == NULL will only happened in consistent_hash
	const EndpointAddress *select_addr = this->select_stradegy(uri);

	if (!select_addr || select_addr->fail_count >= select_addr->params.max_fails)
	{
		select_addr = this->get_one(); // check_one_strong/weak()
		if (!select_addr && this->try_another)
			select_addr = this->another_stradegy();
	}
	addr = select_addr;

	pthread_rwlock_unlock(&this->rwlock);
	return addr != NULL;
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

		if (group_id < group->group_id)
			p = &(*p)->rb_left;
		else if (group_id > group->group_id)
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

	if (addr->params.server_type == 0)
	{
		this->total_weight += addr->params.weight;
		this->main.push_back(addr);
	}

	group->mutex.lock();
	this->gain_one_server(addr);
	addr->group = group;
	if (addr->params.server_type == 0)
	{
		group->weight += addr->params.weight;
		group->mains.push_back(addr);
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
		for (auto addr : map_it->second)
		{
			auto *group = addr->group;
			std::vector<EndpointAddress *> *vec;

			if (addr->params->server_type == 0)
			{
				this->total_weight -= addr->params.weight; // this is for WeightedRandom
				vec = &group->mains;
			}
			else
				vec = &group->backups;

			std::lock_guard<std::mutex> lock(group->mutex);
			if (addr->fail_count < addr->params.max_fails)
				group->lose_one_server(addr);
			if (addr->params.server_type == 0)
				group->weight -= addr->params.weight;
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

	int n = this->servers.size();
	int new_n = 0;

	for (int i = 0; i < n; i++)
	{
		if (this->servers[i]->address != address)
		{
			if (new_n != i)
				this->servers[new_n++] = this->servers[i];
			else
				new_n++;
		}
	}

	if (new_n < n)
	{
		this->servers.resize(new_n);
		pthread_rwlock_unlock(&this->rwlock);
		return n - new_n;
	}

	pthread_rwlock_unlock(&this->rwlock);
	return 0;
}

void GroupPolicy::gain_one_server(const EndpointAddress *addr)
{
	//this->navlive++;
	this->group->gain_one_server();
}

void GroupPolicy::lose_one_server(const EndpointAddress *addr)
{
	this->group->lose_one_server();
}

void WeightedRandomPolicy::gain_one_server(const EndpointAddress *addr)
{
	// TODO:
	this->available_weight += addr->params.weight;
}
*/


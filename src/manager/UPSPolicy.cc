#include "UPSPolicy.h"
#include "StringUtil.h"

#define DNS_CACHE_LEVEL_1		1
#define DNS_CACHE_LEVEL_2		2

class WFSelectorFailTask : public WFRouterTask
{
public:
	WFSelectorFailTask(router_callback_t&& cb)
		: WFRouterTask(std::move(cb))
	{
	}

	virtual void dispatch()
	{
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_UPSTREAM_UNAVAILABLE;

		return this->subtask_done();
	}
};

static bool copy_host_port(ParsedURI& uri, const EndpointAddress *addr)
{
	char *host = NULL;
	char *port = NULL;

	if (!addr->host.empty())
	{
		host = strdup(addr->host.c_str());
		if (!host)
			return false;
	}

	if (addr->port_value > 0)
	{
		port = strdup(addr->port.c_str());
		if (!port)
		{
			free(host);
			return false;
		}
		free(uri.port);
		uri.port = port;
	}

	free(uri.host);
	uri.host = host;
	return true;
}

EndpointAddress::EndpointAddress(const std::string& address,
								 const struct AddressParams *address_params)
{
	std::vector<std::string> arr = StringUtil::split(address, ':');
	this->params = *address_params;
	this->address = address;

	static std::hash<std::string> std_hash;
	for (int i = 0; i < VIRTUAL_GROUP_SIZE; i++)
		this->consistent_hash[i] = std_hash(address + "|v" + std::to_string(i));

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

WFRouterTask *UPSPolicy::create_router_task(const struct WFNSParams *params,
											 	   router_callback_t callback)
{
	EndpointAddress *addr = NULL;
	WFRouterTask *task = NULL;

	if (this->select(params->uri, &addr) && copy_host_port(params->uri, addr))
	{
		const auto *settings = WFGlobal::get_global_settings();
		unsigned int dns_ttl_default = settings->dns_ttl_default;
		unsigned int dns_ttl_min = settings->dns_ttl_min;
		const struct EndpointParams *endpoint_params = &settings->endpoint_params;
		int dns_cache_level = params->retry_times == 0 ? DNS_CACHE_LEVEL_2 :
														 DNS_CACHE_LEVEL_1;
		task = this->create(params, dns_cache_level, dns_ttl_default, dns_ttl_min,
							endpoint_params, std::move(callback));
	}
	else
		task = new WFSelectorFailTask(std::move(callback));

	task->set_cookie(addr);

	return task;
}

inline void UPSPolicy::recover_server_from_breaker(EndpointAddress *addr)
{
	addr->fail_count = 0;
	pthread_mutex_lock(&this->breaker_lock);
	if (addr->list.next)
	{
		list_del(&addr->list);
		addr->list.next = NULL;
		this->recover_one_server(addr);
		//this->server_list_change();
	}
	pthread_mutex_unlock(&this->breaker_lock);
}

inline void UPSPolicy::fuse_server_to_breaker(EndpointAddress *addr)
{
	pthread_mutex_lock(&this->breaker_lock);
	if (!addr->list.next)
	{
		addr->broken_timeout = GET_CURRENT_SECOND + MTTR_SECOND;
		list_add_tail(&addr->list, &this->breaker_list);
		this->fuse_one_server(addr);
		//this->server_list_change();
	}
	pthread_mutex_unlock(&this->breaker_lock);
}

void UPSPolicy::success(RouteManager::RouteResult *result, void *cookie,
					 		   CommTarget *target)
{
	pthread_rwlock_rdlock(&this->rwlock);
	this->recover_server_from_breaker((EndpointAddress *)cookie);
	pthread_rwlock_unlock(&this->rwlock);

	WFDNSResolver::success(result, NULL, target);
}

void UPSPolicy::failed(RouteManager::RouteResult *result, void *cookie,
							  CommTarget *target)
{
	EndpointAddress *server = (EndpointAddress *)cookie;

	pthread_rwlock_rdlock(&this->rwlock);
	int fail_count = ++server->fail_count;
	if (fail_count == server->params.max_fails)
		this->fuse_server_to_breaker(server);

	pthread_rwlock_unlock(&this->rwlock);

	WFDNSResolver::failed(result, NULL, target);
}

void UPSPolicy::check_breaker()
{
	pthread_mutex_lock(&this->breaker_lock);
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
					this->recover_one_server(addr);
				}
				list_del(pos);
				addr->list.next = NULL;
			}
		}
	}
	pthread_mutex_unlock(&this->breaker_lock);
	
	//this->server_list_change();
}

const EndpointAddress *UPSPolicy::first_stradegy(const ParsedURI& uri)
{
	unsigned int idx = rand() % this->servers.size();
	return this->servers[idx];
}

const EndpointAddress *UPSPolicy::another_stradegy(const ParsedURI& uri)
{
	return this->first_stradegy(uri);
}

bool UPSPolicy::select(const ParsedURI& uri, EndpointAddress **addr)
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

void UPSPolicy::__add_server(EndpointAddress *addr)
{
	this->addresses.push_back(addr);
	this->server_map[addr->address].push_back(addr);
	this->servers.push_back(addr);
	this->recover_one_server(addr);
}

int UPSPolicy::__remove_server(const std::string& address)
{
	const auto map_it = this->server_map.find(address);
	if (map_it != this->server_map.cend())
	{
		for (EndpointAddress *addr : map_it->second)
		{
			if (addr->fail_count < addr->params.max_fails) // or not: it has already been -- in nalives
				this->fuse_one_server(addr);
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

	return ret;
}

void UPSPolicy::add_server(const std::string& address,
						   const AddressParams *address_params)
{
	EndpointAddress *addr = new EndpointAddress(address, address_params);

	pthread_rwlock_wrlock(&this->rwlock);
	this->__add_server(addr);
	pthread_rwlock_unlock(&this->rwlock);
}

int UPSPolicy::remove_server(const std::string& address)
{
	int ret;
	pthread_rwlock_wrlock(&this->rwlock);
	ret = this->__remove_server(address);
	pthread_rwlock_unlock(&this->rwlock);
	return ret;
}

int UPSPolicy::replace_server(const std::string& address,
							  const AddressParams *address_params)
{
	int ret;
	EndpointAddress *addr = new EndpointAddress(address, address_params);

	pthread_rwlock_wrlock(&this->rwlock);
	this->__add_server(addr);
	ret = this->__remove_server(address);
	pthread_rwlock_unlock(&this->rwlock);
	return ret;
}

void UPSPolicy::enable_server(const std::string& address)
{
	pthread_rwlock_rdlock(&this->rwlock);
	const auto map_it = this->server_map.find(address);
	if (map_it != this->server_map.cend())
	{
		for (EndpointAddress *addr : map_it->second)
			this->recover_server_from_breaker(addr);
	}
	pthread_rwlock_unlock(&this->rwlock);
}

void UPSPolicy::disable_server(const std::string& address)
{
	pthread_rwlock_rdlock(&this->rwlock);
	const auto map_it = this->server_map.find(address);
	if (map_it != this->server_map.cend())
	{
		for (EndpointAddress *addr : map_it->second)
		{
			addr->fail_count = addr->params.max_fails;
			this->fuse_server_to_breaker(addr);
		}
	}
	pthread_rwlock_unlock(&this->rwlock);
}

void UPSPolicy::get_main_address(std::vector<std::string>& addr_list)
{
	pthread_rwlock_rdlock(&this->rwlock);

	for (const EndpointAddress *server : this->servers)
		addr_list.push_back(server->address);

	pthread_rwlock_unlock(&this->rwlock);
}

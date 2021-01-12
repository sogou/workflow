#include "EndpointParams.h"
#include "WFNameService.h"
#include "WFDNSResolver.h"
#include "WFGlobal.h"
#include "WFTaskError.h"

#include <unordered_map>
#include <vector>

#ifndef _GOVERNANCE_POLICY_H_
#define _GOVERNANCE_POLICY_H_ 

#define MTTR_SECOND			30
#define GET_CURRENT_SECOND  std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count()
//#define VIRTUAL_GROUP_SIZE  16

// or #include "WFTaskFactory.h"
#define DNS_CACHE_LEVEL_1		1
#define DNS_CACHE_LEVEL_2		2

struct AddressParams
{
	struct EndpointParams endpoint_params;
	unsigned int dns_ttl_default;
	unsigned int dns_ttl_min;
	unsigned int max_fails;
	unsigned short weight;
	int server_type;
	int group_id;
};

class EndpointGroup;
class GovernancePolicy;
class GroupPolicy;

class EndpointAddress
{
public:
	EndpointGroup *group;
	AddressParams params;
	std::string address;
	std::string host;
	std::string port;
	short port_value;
	struct list_head list;
	std::atomic<unsigned int> fail_count;
	int64_t broken_timeout;
	// unsigned int consistent_hash[VIRTUAL_GROUP_SIZE];

public:
	EndpointAddress(const std::string& address,
					const struct AddressParams *address_params);
};

class EndpointGroup
{
public:
	int group_id;
	GroupPolicy *policy;
	struct rb_node rb;
	std::mutex mutex;
	std::vector<EndpointAddress *> mains;
	std::vector<EndpointAddress *> backups;
	std::atomic<int> nalive;

	EndpointGroup(int group_id, GroupPolicy *policy)
	{
		this->group_id = group_id;
		this->policy = policy;
		this->nalive = 0;
	}

public:
	const EndpointAddress *get_one();
	const EndpointAddress *get_one_backup();
};

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

class GovernancePolicy : public WFDNSResolver
{
public:
	virtual WFRouterTask *create_router_task(const struct WFNSParams *params,
											 router_callback_t callback);
	virtual void success(RouteManager::RouteResult *result, void *cookie,
					 	 CommTarget *target);
	virtual void failed(RouteManager::RouteResult *result, void *cookie,
						CommTarget *target);

	// GovernancePolicy *gp = dynamic_cast<GovernancePolicy *>(policy); gp->add_server(...);
	virtual void add_server(const std::string& address, const AddressParams *address_params);
	virtual int remove_server(const std::string& address);

	virtual void enable_server(const std::string& address);
	virtual void disable_server(const std::string& address);
	// virtual void server_list_change(/* std::vector<server> status */) {}
private:

public:
	GovernancePolicy()
	{
		this->nalive = 0;
		this->try_another = false;
		pthread_rwlock_init(&this->rwlock, NULL);
		INIT_LIST_HEAD(&this->breaker_list);
	}

	~GovernancePolicy()
	{
		pthread_rwlock_destroy(&this->rwlock);
		for (EndpointAddress *addr : this->addresses)
			delete addr;
	}

private:
	virtual bool select(const ParsedURI& uri, EndpointAddress **addr);
	virtual const EndpointAddress *first_stradegy(const ParsedURI& uri);
	virtual const EndpointAddress *another_stradegy(const ParsedURI& uri);

	virtual void recover_one_server(const EndpointAddress *addr)
	{
		this->nalive++;
	}

	virtual void fuse_one_server(const EndpointAddress *addr)
	{
		this->nalive--;
	}

	void recover_server_from_breaker(EndpointAddress *addr);
	void fuse_server_to_breaker(EndpointAddress *addr);
	void check_breaker();

	bool try_another;
	std::vector<EndpointAddress *> servers; // current servers
	std::vector<EndpointAddress *> addresses; // memory management
	std::unordered_map<std::string,
					   std::vector<EndpointAddress *>> server_map;
	pthread_rwlock_t rwlock;
	struct list_head breaker_list;
	std::mutex breaker_lock;

protected:
	std::atomic<int> nalive;
};

class GroupPolicy : public GovernancePolicy
{
public:
	struct rb_root group_map;
	EndpointGroup *default_group;

private:
	virtual void recover_one_server(const EndpointAddress *addr)
	{
		this->nalive++;
		addr->group->nalive++;
	}

	virtual void fuse_one_server(const EndpointAddress *addr)
	{
		this->nalive--;
		addr->group->nalive--;
	}
	// override: select() add_server() remove_server()
};

/*
class WeightedRandomPolicy : public GroupPolicy
{
public:
	EndpointAddrress *first_stradegy(const ParsedURI& uri)
	{
		int x = 0;
		int s = 0;
		int idx, temp_weight;

		temp_weight = this->total_weight;

		if (temp_weight > 0)
			x = rand() % temp_weight;

		for (idx = 0; idx < this->servers.size(); idx++)
		{
			s += this->servers[idx].params.weight;
			if (s > x)
				break;
		}
		if (idx == this->servers.size())
			idx--;

		return &this->servers[idx];
	}

	EndpointAddrress *another_stradegy(const ParsedURI& uri)
	{
		// weighted_random_try_another();
	}

	WeightedRandomPolicy()
	{
		this->total_weight = 0;
		this->available_weight = 0;
	}

protected:
	int total_weight;
	int available_weight;
};

using select_t = std::function<unsigned int (const char *, const char *, const char *)>;

class ConsistentHashPolicy : public GroupPolicy
{
public:
	ConsistentHashPolicy()
	{
		this->consistent_hash = this->default_consistent_hash;
	}

	ConsistentHashPolicy(select_t select)
	{
		this->consistent_hash = std::move(select);
	}

	EndpointAddrress *another_stradegy(const ParsedURI& uri)
	{
		unsigned int hash_value = this->consistent_hash(uri.path ? uri.path : "",
														uri.query ? uri.query : "",
														uri.fragment ? uri.fragment : "");

		return consistent_hash_select(hash_value);
	}

	EndpointAddrress *first_stradegy(const ParsedURI& uri)
	{
		return NULL;
	}

private:
	select_t consistent_hash;

private:
	const EndpointAddress *consistent_hash_select(unsigned int hash) const
	{
	}

	static unsigned int default_consistent_hash(const char *path,
												const char *query,
												const char *fragment)
	{
	    static std::hash<std::string> std_hash;
	    std::string str(path);

    	str += query;
    	str += fragment;
    	return std_hash(str);
	}
};

class ManualPolicy : public GroupPolicy
{
public:
	ManualPolicy(bool try_another, select_t select, select_t try_another_select)
	{
		this->try_another = try_another;
		this->select = select;
		this->try_another_select = try_another_select;
	}
	
	EndpointAddrress *first_stradegy(const ParsedURI& uri)
	{
    	int idx = this->manual_select(uri.path ? uri.path : "",
                           			  uri.query ? uri.query : "",
                                      uri.fragment ? uri.fragment : ""); 

        if (idx >= n)
            idx %= n;

		return this->servers[idx];
	}

	EndpointAddrress *another_stradegy(const ParsedURI& uri)
	{
		if (this->try_another_select)
		{
			int idx = this->try_another_select(uri.path ? uri.path : "",
											   uri.query ? uri.query : "",
											   uri.fragment ? uri.fragment : "");
			if (idx >= n)
				idx %= n;
			return this->servers[idx];
		}

		// get address after hash_value
		return this->default_consistent_hash_select(uri.path ? uri.path : "",
											 		uri.query ? uri.query : "",
											 		uri.fragment ? uri.fragment : "");
	}

private:
	select_t manual_select;
	select_t try_another_select;
};
*/

#endif


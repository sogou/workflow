class EndpointAddress
{
public:
	AddressParams params;
	std::string address;
	std::string host;
	std::string port;
	unsigned short port_value;
	//...

public:
	EndpointAddress(const std::string& address,
					const struct AddressParams *address_params);
};

//using ENDPOINT_TABLE = std::map<std::string, std::vector<EndpointAddress *>>;
using ENDPOINT_TABLE = std::vector<EndpointAddress *>;

class WFGovernancePolicy : public WFDNSResolver
{
public:
	WFGovernancePolicy()
	{
	}

	virtual WFRouterTask *create_router_task(const struct WFNSParams *params,
											 router_callback_t callback)
	{
		EndpointAddress *addr;

		if (this->select(parmas->uri, this->endpoint_table, addr))
		{
			if (addr.is_sockaddr)
			{
				this->result.cookie = const_cast<EndpointAddress *>(addr);
			}
			auto *task = WFDNSResolver::create_router_task(params, callback);
			task->set_cookie(addr);
			return task;
		}

		return new WFRouterTask(std::move(callback));
	}

	virtual void success(RouteManager::RouteResult *result, void *cookie,
						 CommTarget *target)
	{
		// ... 
		WFDNSResolver::success(result, cookie, target);
	}

	virtual void failed(RouteManager::RouteResult *result, void *cookie,
						CommTarget *target)
	{
		// ...
		WFDNSResolver::failed(result, cookie, target);
	}

private:
	// breaker_list;

public:
	WFGovernancePolicy()
	{
		this->try_another = false;
	}

private:
	virtual bool select(const ParsedURI& uri, const ENDPOINT_TABLE& endpoint_table, EndpointAddr *addr);
	ENDPOINT_TABLE endpoint_table;
	bool try_another;
};

class WFWeightedRandomPolicy : public WFGovernancePolicy
{
public:
	bool select(const ParsedURI& uri, const ENDPOINT_TABLE& endpoint_table, EndpointAddr *addr)
	{
		uri.host = addr->host;
/*
        int x = 0; 
        int s = 0; 
        int temp_weight = total_weight_;

        if (temp_weight > 0) 
            x = rand() % temp_weight;

        if (idx == n)
            idx = n - 1; 
*/
	}
};

using select_t = std::function<unsigned int (const char *, const char *, const char *)>;

class WFConsistentHashPolicy : public WFGovernancePolicy
{
public:
	WFConsistentHashPolicy()
	{
		this->consistent_hash = this->default_consistent_hash;
	}

	WFConsistentHashSelector(select_t select)
	{
		this->consistent_hash = std::move(select);
	}

	bool select(const ParsedURI& uri, const ENDPOINT_TABLE& endpoint_table, EndpointAddr *addr)
	{
		unsigned int hash_value = this->consistent_hash(uri.path ? uri.path : "",
														uri.query ? uri.query : "",
														uri.fragment ? uri.fragment : "");

		EndpointAddress *addr = consistent_hash_select(hash_value);
		// if not available: try another
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

class WFManualSelector : public WFSelector
{
public:
	WFManualSelector(bool try_another, select_t select, select_t try_another_select)
	{
		this->try_another = try_another;
		this->select = select;
		this->try_another_select = try_another_select;
	}
	
	bool select(const ParsedURI& uri, const ENDPOINT_TABLE& endpoint_table, EndpointAddr *addr)
	{
    	int idx = this->manual_select(uri.path ? uri.path : "",
                           			  uri.query ? uri.query : "",
                                      uri.fragment ? uri.fragment : ""); 

        if (idx >= n)
            idx %= n;

		EndpointAddress *addr = endpoint_table[idx];
		// if not available: try another
	}

private:
	select_t manual_select;
	select_t try_another_select;
};

/*
class WFSelectorTask : public WFRouterTask
{
private:
	virtual void dispatch()
	{
		found = this->policy->selector->select(this->result);

		if (!found)
		{
			//for upstream: create_dns_task...
			//for sosclient: create_cs_route_task(selector_callback)
			series_of(this)->push_front(new_task);
		}

		return this->subtask_done;
	}


};
*/


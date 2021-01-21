#include "UPSPolicy.h"

const EndpointAddress *UPSWeightedRandomPolicy::first_stradegy(const ParsedURI& uri)
{
	int x = 0;
	int s = 0;
	int idx, temp_weight;

	temp_weight = this->total_weight;

	if (temp_weight > 0)
		x = rand() % temp_weight;

	for (idx = 0; idx < this->servers.size(); idx++)
	{
		s += this->servers[idx]->params.weight;
		if (s > x)
			break;
	}
	if (idx == this->servers.size())
		idx--;

	return this->servers[idx];
}

const EndpointAddress *UPSWeightedRandomPolicy::another_stradegy(const ParsedURI& uri)
{
	int temp_weight = this->available_weight;
	if (temp_weight == 0)
		return NULL;

	const EndpointAddress *addr = NULL;
	int x = rand() % temp_weight;
	int s = 0;

	for (const EndpointAddress *server : this->servers)
	{
		if (this->is_alive_or_group_alive(server))
		{
			addr = server;
			s += server->params.weight;
			if (s > x)
				break;
		}
	}
	return this->check_and_get(addr);
}


void UPSWeightedRandomPolicy::recover_one_server(const EndpointAddress *addr)
{
	this->nalives++;
	if (addr->group->nalives++ == 0 && addr->group->id > 0)
		this->available_weight += addr->group->weight;

	if (addr->params.group_id < 0 && addr->params.server_type == 0) // TODO
		this->available_weight += addr->params.weight;
}

void UPSWeightedRandomPolicy::fuse_one_server(const EndpointAddress *addr)
{
	this->nalives--;
	if (--addr->group->nalives == 0 && addr->group->id > 0)
		this->available_weight -= addr->group->weight;

	if (addr->params.group_id < 0 && addr->params.server_type == 0) // TODO
		this->available_weight -= addr->params.weight;
}

const EndpointAddress *UPSConsistentHashPolicy::first_stradegy(const ParsedURI& uri)
{
	unsigned int hash_value;

	if (this->consistent_hash)
		hash_value = this->consistent_hash(uri.path ? uri.path : "",
										   uri.query ? uri.query : "",
										   uri.fragment ? uri.fragment : "");
	else
		hash_value = this->default_consistent_hash(uri.path ? uri.path : "",
												   uri.query ? uri.query : "",
												   uri.fragment ? uri.fragment : "");
	return this->consistent_hash_with_group(hash_value);
}

const EndpointAddress *UPSManualPolicy::first_stradegy(const ParsedURI& uri)
{
	int idx = this->manual_select(uri.path ? uri.path : "",
								  uri.query ? uri.query : "",
								  uri.fragment ? uri.fragment : ""); 

	if (idx >= this->servers.size())
		idx %= this->servers.size();

	return this->servers[idx];
}

const EndpointAddress *UPSManualPolicy::another_stradegy(const ParsedURI& uri)
{
	unsigned int hash_value;

	if (this->try_another_select)
		hash_value = this->try_another_select(uri.path ? uri.path : "",
											  uri.query ? uri.query : "",
											  uri.fragment ? uri.fragment : "");
	else
		hash_value = UPSConsistentHashPolicy::default_consistent_hash(uri.path ? uri.path : "",
																   uri.query ? uri.query : "",
																   uri.fragment ? uri.fragment : "");
	return this->consistent_hash_with_group(hash_value);
}


/*
  Copyright (c) 2022 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Authors: Wang Zhenpeng (wangzhenpeng@sogou-inc.com)
*/

#ifndef _CONSULDATATYPES_H_
#define _CONSULDATATYPES_H_

#include <assert.h>
#include <atomic>
#include <map>
#include <vector>
#include <string>

namespace protocol
{

class ConsulConfig
{
public:
	// common config
	void set_token(const std::string& token) { this->ptr->token = token; }
	std::string get_token() const { return this->ptr->token;  }

	// discover config

	void set_datacenter(const std::string& data_center)
	{
		this->ptr->dc = data_center;
	}
	std::string get_datacenter() const { return this->ptr->dc; }

	void set_near_node(const std::string& near_node)
	{
		this->ptr->near = near_node;
	}
	std::string get_near_node() const { return this->ptr->near; }

	void set_filter_expr(const std::string& filter_expr)
	{
		this->ptr->filter = filter_expr;
	}
	std::string get_filter_expr() const { return this->ptr->filter; }

	// blocking query wait, limited to 10 minutes, default:5m, unit:ms
	void set_wait_ttl(int wait_ttl) { this->ptr->wait_ttl = wait_ttl; }
	int get_wait_ttl() const { return this->ptr->wait_ttl; }

	// enable blocking query
	void set_blocking_query(bool enable_flag)
	{
		this->ptr->blocking_query = enable_flag;
	}
	bool blocking_query() const { return this->ptr->blocking_query; }

	// only get health passing status service instance
	void set_passing(bool passing) { this->ptr->passing = passing; }
	bool get_passing() const { return this->ptr->passing; }


	// register config

	void set_replace_checks(bool replace_checks)
	{
		this->ptr->replace_checks = replace_checks;
	}
	bool get_replace_checks() const
	{
		return this->ptr->replace_checks;
	}
	
	void set_check_name(const std::string& check_name)
	{
		this->ptr->check_cfg.check_name = check_name;
	}
	std::string get_check_name() const { return this->ptr->check_cfg.check_name; }

	void set_check_http_url(const std::string& http_url)
	{
		this->ptr->check_cfg.http_url = http_url;
	}
	std::string get_check_http_url() const
	{
		return this->ptr->check_cfg.http_url;
	}

	void set_check_http_method(const std::string& method)
	{
		this->ptr->check_cfg.http_method = method;
	}
	std::string get_check_http_method() const
	{
		return this->ptr->check_cfg.http_method;
	}

	void add_http_header(const std::string& key,
						 const std::vector<std::string>& values)
	{
		this->ptr->check_cfg.headers.emplace(key, values);
	}
	const std::map<std::string, std::vector<std::string>> *get_http_headers() const
	{
		return &this->ptr->check_cfg.headers;
	}

	void set_http_body(const std::string& body)
	{
		this->ptr->check_cfg.http_body = body;
	}
	std::string get_http_body() const { return this->ptr->check_cfg.http_body; }

	void set_check_interval(int interval)
	{
		this->ptr->check_cfg.interval = interval;
	}
	int get_check_interval() const { return this->ptr->check_cfg.interval; }

	void set_check_timeout(int timeout)
	{
		this->ptr->check_cfg.timeout = timeout;
	}
	int get_check_timeout() const { return this->ptr->check_cfg.timeout; }

	void set_check_notes(const std::string& notes)
	{
		this->ptr->check_cfg.notes = notes;
	}
	std::string get_check_notes() const { return this->ptr->check_cfg.notes; }

	void set_check_tcp(const std::string& tcp_address)
	{
		this->ptr->check_cfg.tcp_address = tcp_address;
	}
	std::string get_check_tcp() const { return this->ptr->check_cfg.tcp_address; }

	void set_initial_status(const std::string& initial_status)
	{
		this->ptr->check_cfg.initial_status = initial_status;
	}
	std::string get_initial_status() const
	{
		return this->ptr->check_cfg.initial_status;
	}

	void set_auto_deregister_time(int milliseconds)
	{
		this->ptr->check_cfg.auto_deregister_time = milliseconds;
	}
	int get_auto_deregister_time() const
	{
		return this->ptr->check_cfg.auto_deregister_time;
	}

	// set success times before passing, refer to success_before_passing, default:0
	void set_success_times(int times)
	{ 
		this->ptr->check_cfg.success_times = times;
	}
	int get_success_times() const { return this->ptr->check_cfg.success_times; }

	// set failure times before critical, refer to failures_before_critical, default:0
	void set_failure_times(int times) { this->ptr->check_cfg.failure_times = times; }
	int get_failure_times() const { return this->ptr->check_cfg.failure_times; }

	void set_health_check(bool enable_flag)
	{
		this->ptr->check_cfg.health_check = enable_flag;
	}
	bool get_health_check() const
	{
		return this->ptr->check_cfg.health_check;
	}

public:
	ConsulConfig()
	{
		this->ptr = new Config;	
		this->ptr->blocking_query = false;
		this->ptr->passing = false;
		this->ptr->replace_checks = false;
		this->ptr->wait_ttl = 300 * 1000;
		this->ptr->check_cfg.interval = 5000;
		this->ptr->check_cfg.timeout = 10000;
		this->ptr->check_cfg.http_method = "GET";
		this->ptr->check_cfg.initial_status = "critical";
		this->ptr->check_cfg.auto_deregister_time = 10 * 60 * 1000;
		this->ptr->check_cfg.success_times = 0;
		this->ptr->check_cfg.failure_times = 0;
		this->ptr->check_cfg.health_check = false;

		this->ref = new std::atomic<int>(1);
	}

	virtual ~ConsulConfig()
	{
		if (--*this->ref == 0)
		{
			delete this->ptr;
			delete this->ref;
		}
	}

	ConsulConfig(ConsulConfig&& move)
	{
		this->ptr = move.ptr;
		this->ref = move.ref;
		move.ptr = new Config;
		move.ref = new std::atomic<int>(1);
	}

	ConsulConfig(const ConsulConfig& copy)
	{
		this->ptr = copy.ptr;
		this->ref = copy.ref;
		++(*this->ref);
	}

	ConsulConfig& operator= (ConsulConfig&& move)
	{
		if (this != &move)
		{
			this->~ConsulConfig();
			this->ptr = move.ptr;
			this->ref = move.ref;
			move.ptr = new Config;
			move.ref = new std::atomic<int>(1);
		}

		return *this;
	}

	ConsulConfig& operator= (const ConsulConfig& copy)
	{
		if (this != &copy)
		{
			this->~ConsulConfig();
			this->ptr = copy.ptr;
			this->ref = copy.ref;
			++(*this->ref);
		}

		return *this;
	}

private:
	// register health check config
	struct HealthCheckConfig
	{
		std::string check_name;
		std::string notes;
		std::string http_url;
		std::string http_method;
		std::string http_body;
		std::string tcp_address;
		std::string initial_status; // passing or critical, default:critical
		std::map<std::string, std::vector<std::string>> headers;
		int auto_deregister_time; // refer to deregister_critical_service_after
		int interval;
		int timeout; // default 10000
		int success_times; // default:0 success times before passing
		int failure_times; // default:0 failure_before_critical
		bool health_check;
	};

	struct Config
	{
		// common config
		std::string token;

		// discover config
		std::string dc;
		std::string near;
		std::string filter;
		int wait_ttl;
		bool blocking_query;
		bool passing;

		// register config
		bool replace_checks; //refer to replace_existing_checks
		HealthCheckConfig check_cfg;
	};

private:
	struct Config *ptr;
	std::atomic<int> *ref;
};

// k:address, v:port
using ConsulAddress = std::pair<std::string, unsigned short>;

struct ConsulService
{
	std::string service_name;
	std::string service_namespace;
	std::string service_id;
	std::vector<std::string> tags;
	ConsulAddress service_address;
	ConsulAddress lan;
	ConsulAddress lan_ipv4;
	ConsulAddress lan_ipv6;
	ConsulAddress virtual_address; 
	ConsulAddress wan;
	ConsulAddress wan_ipv4;
	ConsulAddress wan_ipv6;
	std::map<std::string, std::string> meta;
	bool tag_override;
};

struct ConsulServiceInstance
{
	// node info
	std::string node_id;
	std::string node_name;
	std::string node_address;
	std::string dc;
	std::map<std::string, std::string> node_meta;
	long long create_index;
	long long modify_index;

	// service info
	struct ConsulService service;

	// service health check
	std::string check_name;
	std::string check_id;
	std::string check_notes;
	std::string check_output;
	std::string check_status;
	std::string check_type;
};

struct ConsulServiceTags
{
	std::string service_name;
	std::vector<std::string> tags;
};

}

#endif

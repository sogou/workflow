/*
  Copyright (c) 2019 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Authors: Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

#ifndef _DNSROUTINE_H_
#define _DNSROUTINE_H_

#include <netdb.h>
#include <string>

class DnsInput
{
public:
	DnsInput() :
		port_(0),
		numeric_host_(false)
	{}

	DnsInput(const std::string& host, unsigned short port,
			 bool numeric_host) :
		host_(host),
		port_(port),
		numeric_host_(numeric_host)
	{}

	//move constructor
	DnsInput(DnsInput&& move) = default;
	//move operator
	DnsInput& operator= (DnsInput &&move) = default;

	void reset(const std::string& host, unsigned short port)
	{
		host_.assign(host);
		port_ = port;
		numeric_host_ = false;
	}

	void reset(const std::string& host, unsigned short port,
			   bool numeric_host)
	{
		host_.assign(host);
		port_ = port;
		numeric_host_ = numeric_host;
	}

	const std::string& get_host() const { return host_; }
	unsigned short get_port() const { return port_; }
	bool is_numeric_host() const { return numeric_host_; }

protected:
	std::string host_;
	unsigned short port_;
	bool numeric_host_;

	friend class DnsRoutine;
};

class DnsOutput
{
public:
	DnsOutput():
		error_(0),
		addrinfo_(NULL)
	{}

	~DnsOutput()
	{
		if (addrinfo_)
			freeaddrinfo(addrinfo_);
	}

	//move constructor
	DnsOutput(DnsOutput&& move);
	//move operator
	DnsOutput& operator= (DnsOutput&& move);

	int get_error() const { return error_; }
	const struct addrinfo *get_addrinfo() const { return addrinfo_; }

	//if DONOT want DnsOutput release addrinfo, use move_addrinfo in callback
	struct addrinfo *move_addrinfo()
	{
		struct addrinfo *p = addrinfo_;
		addrinfo_ = NULL;
		return p;
	}

protected:
	int error_;
	struct addrinfo *addrinfo_;

	friend class DnsRoutine;
};

class DnsRoutine
{
public:
	static void run(const DnsInput *in, DnsOutput *out);
	static void create(DnsOutput *out, int error, struct addrinfo *ai)
	{
		if (out->addrinfo_)
			freeaddrinfo(out->addrinfo_);

		out->error_ = error;
		out->addrinfo_ = ai;
	}

private:
	static void run_local_path(const std::string& path, DnsOutput *out);
};

//new WFDnsTask(queue, executor, dns_routine, callback)
//if donot want freeaddrinfo, please std::move output in callback

#endif


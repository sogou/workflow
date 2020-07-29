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

#include <stdio.h>
#include <sys/un.h>
#include "DNSRoutine.h"

#define PORT_STR_MAX	5

DNSOutput::DNSOutput(DNSOutput&& move)
{
	error_ = move.error_;
	addrinfo_ = move.addrinfo_;

	move.error_ = 0;
	move.addrinfo_ = NULL;
}

DNSOutput& DNSOutput::operator= (DNSOutput&& move)
{
	if (this != &move)
	{
		if (addrinfo_)
			freeaddrinfo(addrinfo_);

		error_ = move.error_;
		addrinfo_ = move.addrinfo_;

		move.error_ = 0;
		move.addrinfo_ = NULL;
	}

	return *this;
}

void DNSRoutine::run(const DNSInput *in, DNSOutput *out)
{
	if (!in->host_.empty() && in->host_[0] == '/')
	{
		out->error_ = 0;
		out->addrinfo_ = (addrinfo*)malloc(sizeof (struct addrinfo) + sizeof (struct sockaddr_un));
		out->addrinfo_->ai_flags = AI_ADDRCONFIG;
		out->addrinfo_->ai_family = AF_UNIX;
		out->addrinfo_->ai_socktype = SOCK_STREAM;
		out->addrinfo_->ai_protocol = 0;
		out->addrinfo_->ai_addrlen = sizeof (struct sockaddr_un);
		out->addrinfo_->ai_addr = (struct sockaddr *)((char *)(out->addrinfo_) + sizeof (struct addrinfo));
		out->addrinfo_->ai_canonname = NULL;
		out->addrinfo_->ai_next = NULL;
		struct sockaddr_un *sun = (struct sockaddr_un *)(out->addrinfo_->ai_addr);

		sun->sun_family = AF_UNIX;
		memset(sun->sun_path, 0, sizeof (sun->sun_path));
		strcpy(sun->sun_path, in->host_.c_str());
		return;
	}

	struct addrinfo hints = {
#ifdef AI_ADDRCONFIG
		.ai_flags    = AI_ADDRCONFIG,
#endif
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM
	};
	char port_str[PORT_STR_MAX + 1];

	snprintf(port_str, PORT_STR_MAX + 1, "%u", in->port_);
	out->error_ = getaddrinfo(in->host_.c_str(),
							  port_str,
							  &hints,
							  &out->addrinfo_);
}


/*
  Copyright (c) 2021 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

	  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Xie Han (xiehan@sogou-inc.com;63350856@qq.com)
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <string>
#include "workflow/WFGlobal.h"
#include "workflow/WFNameService.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/WFFacilities.h"
#include "workflow/HttpUtil.h"

// The example domonstrate the simplest user defined naming policy.

/* 'MyNSPolicy' is a naming policy, which use local file for naming.
 * The format of naming file is similar to 'hosts' file, but we allow
 * domain name and IP address as destination. For example:
 *
 * 127.0.0.1 localhost
 * 127.0.0.1 mydomain  # another alias for 127.0.0.1
 * www.sogou.com sogou # sogou -> www.sogou.com
 */
class MyNSPolicy : public WFNSPolicy
{
public:
	WFRouterTask *create_router_task(const struct WFNSParams *params,
									 router_callback_t callback) override;

private:
	std::string path;

private:
	std::string read_from_fp(FILE *fp, const char *name);
	std::string parse_line(char *p, const char *name);

public:
	MyNSPolicy(const char *naming_file) : path(naming_file) { }
};

std::string MyNSPolicy::parse_line(char *p, const char *name)
{
	const char *dest = NULL;
	char *start;

	start = p;
	while (*start != '\0' && *start != '#')
		start++;
	*start = '\0';

	while (1)
	{
		while (isspace(*p))
			p++;

		start = p;
		while (*p != '\0' && !isspace(*p))
			p++;

		if (start == p)
			break;

		if (*p != '\0')
			*p++ = '\0';

		if (dest == NULL)
		{
			dest = start;
			continue;
		}

		if (strcasecmp(name, start) == 0)
			return std::string(dest);
	}

	return std::string();
}

std::string MyNSPolicy::read_from_fp(FILE *fp, const char *name)
{
	char *line = NULL;
	size_t bufsize = 0;
	std::string result;

	while (getline(&line, &bufsize, fp) > 0)
	{
		result = this->parse_line(line, name);
		if (result.size() > 0)
			break;
	}

	free(line);
	return result;
}

WFRouterTask *MyNSPolicy::create_router_task(const struct WFNSParams *params,
											 router_callback_t callback)
{
	WFDnsResolver *dns_resolver = WFGlobal::get_dns_resolver();

	if (params->uri.host)
	{
		FILE *fp = fopen(this->path.c_str(), "r");
		if (fp)
		{
			std::string dest = this->read_from_fp(fp, params->uri.host);
			if (dest.size() > 0)
			{
				/* Update the uri structure's 'host' field directly.
				 * You can also update the 'port' field if needed. */
				free(params->uri.host);
				params->uri.host = strdup(dest.c_str());
			}

			fclose(fp);
		}
	}

	/* Simply, use the global dns resolver to create a router task. */
	return dns_resolver->create_router_task(params, std::move(callback));
}

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		fprintf(stderr, "USAGE: %s <http url> <naming file>\n", argv[0]);
		exit(1);
	}

	ParsedURI uri;
	URIParser::parse(argv[1], uri);
	char *name = uri.host;
	if (name == NULL)
	{
		fprintf(stderr, "Invalid http URI\n");
		exit(1);
	}

	/* Create an naming policy. */
	MyNSPolicy *policy = new MyNSPolicy(argv[2]);

	/* Get the global name service object.*/
	WFNameService *ns = WFGlobal::get_name_service();

	/* Add the our name with policy to global name service.
	 * You can add mutilply names with one policy object. */
	ns->add_policy(name, policy);

	WFFacilities::WaitGroup wg(1);
	WFHttpTask *task = WFTaskFactory::create_http_task(argv[1], 2, 3,
		[&wg](WFHttpTask *task) {
			int state = task->get_state();
			int error = task->get_error();
			if (state != WFT_STATE_SUCCESS)
			{
				fprintf(stderr, "error: %s\n",
						WFGlobal::get_error_string(state, error));
			}
			else
			{
				auto *r = task->get_resp();
				std::string body = protocol::HttpUtil::decode_chunked_body(r);
				fwrite(body.c_str(), 1, body.size(), stdout);
			}
			wg.done();
		});

	task->start();
	wg.wait();

	/* clean up */
	ns->del_policy(name);
	delete policy;
	return 0;
}


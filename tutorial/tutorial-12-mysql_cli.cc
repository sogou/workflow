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

  Authors: Li Yingxin (liyingxin@sogou-inc.com)
*/

#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <vector>
#include <map>
#include "workflow/Workflow.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/MySQLResult.h"
#include "workflow/WFFacilities.h"

using namespace protocol;

#define RETRY_MAX       0

volatile bool stop_flag;

void mysql_callback(WFMySQLTask *task);

void get_next_cmd(WFMySQLTask *task)
{
	int len;
	char query[4096];
	WFMySQLTask *next_task;

	fprintf(stderr, "mysql> ");
	while ((fgets(query, 4096, stdin)) && stop_flag == false)
	{
		len = strlen(query);
		if (len > 0 && query[len - 1] == '\n')
			query[len - 1] = '\0';

		if (strncmp(query, "quit", len) == 0 || 
			strncmp(query, "exit", len) == 0)
		{
			fprintf(stderr, "Bye\n");
			return;
		}

		if (len == 0 || strncmp(query, "\0", len) == 0)
		{
			fprintf(stderr, "mysql> ");
			continue;
		}

		std::string *url = (std::string *)series_of(task)->get_context();
		next_task = WFTaskFactory::create_mysql_task(*url, RETRY_MAX, mysql_callback);
		next_task->get_req()->set_query(query);
		series_of(task)->push_back(next_task);	
		break;
	}
	return;
}

void mysql_callback(WFMySQLTask *task)
{
	MySQLResponse *resp = task->get_resp();

	MySQLResultCursor cursor(resp);
	const MySQLField *const *fields;
	std::vector<MySQLCell> arr;

	if (task->get_state() != WFT_STATE_SUCCESS)
	{
		fprintf(stderr, "error msg: %s\n",
				WFGlobal::get_error_string(task->get_state(),
										   task->get_error()));
		return;
	}

	do {
		if (cursor.get_cursor_status() != MYSQL_STATUS_GET_RESULT &&
			cursor.get_cursor_status() != MYSQL_STATUS_OK)
		{
			break;
		}

		fprintf(stderr, "---------------- RESULT SET ----------------\n");

		if (cursor.get_cursor_status() == MYSQL_STATUS_GET_RESULT)
		{
			fprintf(stderr, "cursor_status=%d field_count=%u rows_count=%u\n",
					cursor.get_cursor_status(), cursor.get_field_count(),
					cursor.get_rows_count());

			//nocopy api
			fields = cursor.fetch_fields();
			for (int i = 0; i < cursor.get_field_count(); i++)
			{
				if (i == 0)
				{
					fprintf(stderr, "db=%s table=%s\n",
						fields[i]->get_db().c_str(), fields[i]->get_table().c_str());
					fprintf(stderr, "  ---------- COLUMNS ----------\n");
				}
				fprintf(stderr, "  name[%s] type[%s]\n",
						fields[i]->get_name().c_str(),
						datatype2str(fields[i]->get_data_type()));
			}
			fprintf(stderr, "  _________ COLUMNS END _________\n\n");

			while (cursor.fetch_row(arr))
			{
				fprintf(stderr, "  ------------ ROW ------------\n");
				for (size_t i = 0; i < arr.size(); i++)
				{
					fprintf(stderr, "  [%s][%s]", fields[i]->get_name().c_str(),
							datatype2str(arr[i].get_data_type()));
					if (arr[i].is_string())
					{
						std::string res = arr[i].as_string();
						if (res.length() == 0)
							fprintf(stderr, "[\"\"]\n");
						else 
							fprintf(stderr, "[%s]\n", res.c_str());
					} else if (arr[i].is_int()) {
						fprintf(stderr, "[%d]\n", arr[i].as_int());
					} else if (arr[i].is_ulonglong()) {
						fprintf(stderr, "[%llu]\n", arr[i].as_ulonglong());
					} else if (arr[i].is_float()) {
						const void *ptr;
						size_t len;
						int data_type;
						arr[i].get_cell_nocopy(&ptr, &len, &data_type);
						size_t pos;
						for (pos = 0; pos < len; pos++)
							if (*((const char *)ptr + pos) == '.')
								break;
						if (pos != len)
							pos = len - pos - 1;
						else
							pos = 0;
						fprintf(stderr, "[%.*f]\n", (int)pos, arr[i].as_float());
					} else if (arr[i].is_double()) {
						const void *ptr;
						size_t len;
						int data_type;
						arr[i].get_cell_nocopy(&ptr, &len, &data_type);
						size_t pos;
						for (pos = 0; pos < len; pos++)
							if (*((const char *)ptr + pos) == '.')
								break;
						if (pos != len)
							pos = len - pos - 1;
						else
							pos= 0;
						fprintf(stderr, "[%.*lf]\n", (int)pos, arr[i].as_double());
					} else if (arr[i].is_date()) {
						fprintf(stderr, "[%s]\n", arr[i].as_string().c_str());
					} else if (arr[i].is_time()) {
						fprintf(stderr, "[%s]\n", arr[i].as_string().c_str());
					} else if (arr[i].is_datetime()) {
						fprintf(stderr, "[%s]\n", arr[i].as_string().c_str());
					} else if (arr[i].is_null()) {
						fprintf(stderr, "[NULL]\n");
					} else {
						std::string res = arr[i].as_binary_string();
						if (res.length() == 0)
							fprintf(stderr, "[\"\"]\n");
						else 
							fprintf(stderr, "[%s]\n", res.c_str());
					}
				}
				fprintf(stderr, "  __________ ROW END __________\n");
			}
		}
		else if (cursor.get_cursor_status() == MYSQL_STATUS_OK)
		{
			fprintf(stderr, "  OK. %llu ", cursor.get_affected_rows());
			if (cursor.get_affected_rows() == 1)
				fprintf(stderr, "row ");
			else
				fprintf(stderr, "rows ");
			fprintf(stderr, "affected. %d warnings. insert_id=%llu. %s\n",
					cursor.get_warnings(), cursor.get_insert_id(),
					cursor.get_info().c_str());
		}

		fprintf(stderr, "________________ RESULT SET END ________________\n\n");
	} while (cursor.next_result_set());


	if (resp->get_packet_type() == MYSQL_PACKET_ERROR)
	{
		fprintf(stderr, "ERROR. error_code=%d %s\n",
				task->get_resp()->get_error_code(),
				task->get_resp()->get_error_msg().c_str());
	}
	else if (resp->get_packet_type() == MYSQL_PACKET_OK) // just check origin APIs
	{
		fprintf(stderr, "OK. %llu ", task->get_resp()->get_affected_rows());
		if (task->get_resp()->get_affected_rows() == 1)
			fprintf(stderr, "row ");
		else
			fprintf(stderr, "rows ");
		fprintf(stderr, "affected. %d warnings. insert_id=%llu. %s\n",
				task->get_resp()->get_warnings(),
				task->get_resp()->get_last_insert_id(),
				task->get_resp()->get_info().c_str());
	}

	get_next_cmd(task);
	return;
}

static void sighandler(int signo)
{
	stop_flag = true;
}

int main(int argc, char *argv[])
{
	WFMySQLTask *task;

	if (argc != 2)
	{
		fprintf(stderr, "USAGE: %s <url>\n"
				"      url format: mysql://root:password@host:port/dbname?character_set=charset\n"
				"      example: mysql://root@test.mysql.com/test\n",
				argv[0]);
		return 0;
	}

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

	std::string url = argv[1];
	if (strncasecmp(argv[1], "mysql://", 8) != 0 &&
		strncasecmp(argv[1], "mysqls://", 9) != 0)
	{
		url = "mysql://" + url;
	}

	const char *query = "show databases";
	stop_flag = false;

	task = WFTaskFactory::create_mysql_task(url, RETRY_MAX, mysql_callback);
	task->get_req()->set_query(query);

	WFFacilities::WaitGroup wait_group(1);
	SeriesWork *series = Workflow::create_series_work(task,
		[&wait_group](const SeriesWork *series) {
			wait_group.done();
		});

	series->set_context(&url);
	series->start();

	wait_group.wait();
	return 0;
}

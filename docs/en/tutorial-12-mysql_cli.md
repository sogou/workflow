# Asynchronous MySQL client: mysql\_cli

# Sample code

[tutorial-12-mysql\_cli.cc](../tutorial/tutorial-12-mysql_cli.cc)

# About mysql\_cli

The mysql\_cli in the tutorial is used in a way similar to the official client. It is an asynchronous MySQL client with an interactive command line interface.

Run the program with the command: ./mysql_cli \<URL\>

After startup, you can directly enter MySQL command in the terminal to interact with db, or enter quit or Ctrl-C to exit.

# Format of MySQL URL

mysql://username:password@host:port/dbname?character\_set=charset

- fill in username and password according to the requirements;

- the default port number is 3306;

- dbname is the name of the database to be used. It is recommended to fill in the db name if SQL statements only operates on one db;

- If you have upstream selection requirements at this level, please see [upstream documents](../docs/about-upstream.md).

- charset indicates a character set; the default value is utf8. For details, please see official MySQL documents [character-set.html](https://dev.mysql.com/doc/internals/en/character-set.html).

Sample MySQL URL:

mysql://root:password@127.0.0.1

mysql://@test.mysql.com:3306/db1?character\_set=utf8

# Creating and starting a MySQL task

You can use WFTaskFactory to create a MySQL task. The creation interface and callback functions are used in a way similar to other tasks in the workflow:

~~~cpp
using mysql_callback_t = std::function<void (WFMySQLTask *)>;

WFMySQLTask *create_mysql_task(const std::string& url, int retry_max, mysql_callback_t callback);

void set_query(const std::string& query);
~~~

You can call **set\_query()** on req to write SQL statements after creating a WFMySQLTask.

According to the MySQL protocol, if an empty packet is sent after the connection is established, the server will wait instead of returning a packet, so the user will get a timeout. Therefore, the framework makes special check on those task that do not call `set_query()` and will immediately return **WFT\_ERR\_MYSQL\_QUERY\_NOT\_SET**.

Others functions, including callback, series and user\_data are used in a way similar to other tasks in the workflow.

The following code shows some general usage:
~~~cpp
int main(int argc, char *argv[])
{
    ...
    WFMySQLTask *task = WFTaskFactory::create_mysql_task(url, RETRY_MAX, mysql_callback);
    task->get_req()->set_query("SHOW TABLES;");
    ...
    task->start();
    ...
}
~~~

# Supported commands

Currently the supported command is **COM\_QUERY**, which can cover the basic requirements for adding, deleting, modifying and querying data, creating and deleting databases, creating and deleting tables, preparing, using stored procedures and using transactions.

Because the program don't support the selection of databases (**US**E command) in our interactive commands, if there are **cross-database** operations in SQL statements, you can specify the database and table with **db \_ name.table \_ name**.

**Multiple commands** can be spliced together and then passed to WFMySQLTask with `set_query()`. Generally speaking, multiple statements can get all the results back at one time. However, due to the incompatibility between the packet reply method in the MySQL protocol and our question-and-answer communication in some special cases, please read the following cautions before you add the SQL statements in `set_query()`:

- For the statement that gets a single result set, multiple statements can be spliced (ordinary INSERT/UPDATE/SELECT/PREPARE)

- The statement that returns multiple result sets (such as CALL a stored procedure) is also supported.

- In other cases, it is recommended to divide SQL statements into individual requests

For example:

~~~cpp
// 单结果集的多条语句拼接，可以正确拿到返回结果
req->set_query("SELECT * FROM table1; SELECT * FROM table2; INSERT INTO table3 (id) VALUES (1);");

// 多结果集的单条语句，也可以正确拿到返回结果
req->set_query("CALL procedure1();");

// 多结果集与其他拼接都不能完全拿到所有返回结果
req->set_query("CALL procedure1(); SELECT * FROM table1;");
~~~

# Parsing results

Similar to other tasks in the workflow, you can use **task->get\_resp()** to get **MySQLResponse**, and you can use **MySQLResultCursor** to traverse the result set, the infomation of each column of the result set(**MySQLField**), each row and each **MySQLCell**. For details on the interfaces, please see [MySQLResult.h](../src/protocol/MySQLResult.h).

The specific steps from the external to the internal should be:

1. checking the task state (state at communication level): you can check whether the task is successfully executed by checking whether **task->get\_state()** is equal to WFT\_STATE\_SUCCESS;

2. determining the type of the reply packet (the parsing status of the return packet): call **resp->get\_packet\_type()** to check the type of the MySQL return packet. The common types include:

- MYSQL\_PACKET\_OK: non-result set requests: parsed successfully;
- MYSQL\_PACKET\_EOF: result set requests: parsed successfully;
- MYSQL\_PACKET\_ERROR: requests: failed;

3. checking the result set state (the state for reading the result sets): you can use MySQLResultCursor to read the content in the result set. Because the data returned by a MySQL server contains multiple result sets, the cursor will **automatically point to the reading position of the first result set** at first. **cursor->get\_cursor\_status()** returns the following states:

- MYSQL\_STATUS\_GET\_RESULT: the data are available to read;
- MYSQL\_STATUS\_END: the last record of the current result set has been read;
- MYSQL\_STATUS\_EOF: all result sets are fetched;
- MYSQL\_STATUS\_OK: the reply packet is a non-result set packet, so you do not need to read data through the result set interface;
- MYSQL\_STATUS\_ERROR: parsing error;

4. reading each field of the columns:

- `int get_field_count() const;`
- `const MySQLField *fetch_field();`
  - `const MySQLField *const *fetch_fields() const;`

5. reading each line: you can use **cursor->fetch\_row()** to read by row until the return value is false, in which the offset within the cursor that points to the row in the current result set will be moved:

- `int get_rows_count() const;`
- `bool fetch_row(std::vector<MySQLCell>& row_arr);`
- `bool fetch_row(std::map<std::string, MySQLCell>& row_map);`
- `bool fetch_row(std::unordered_map<std::string, MySQLCell>& row_map);`
- `bool fetch_row_nocopy(const void **data, size_t *len, int *data_type);`

6. taking out all the rows in the current result set directly: you can use **cursor->fetch\_all()** to read all rows, and the cursor that is used to record the rows internally will be moved directly to the end; The cursor state changes to MYSQL\_STATUS\_END:

- `bool fetch_all(std::vector<std::vector<MySQLCell>>& rows);`

7. returning to the head of the current result set: if it is necessary to read this result set again, you can use **cursor->rewind()** to return to the head of the current result set, and then read it via the operations in Step 5 or Step 6;

8. getting the next result set: because the data packet returned by MySQL server may contain multiple result sets (for example, each select statement gets a result set; or the multiple result sets returned by calling a procedure). Therefore, you can use **cursor->next\_result\_set()**  to jump to the next result set. If the return value is false, it means that all result sets have been taken.

9. returning to the first result set: use **cursor->first\_result\_set()** to return to the heads of all result sets, and then you can repeat the operations from Step 3.

10. getting the data of each column (MySQLCell): the row read in Step 5 is composed of multiple columns, and the result of each column is one MySQLCell. It mainly uses the following interfaces:

- `int get_data_type();` returns MYSQL\_TYPE\_LONG, MYSQL\_TYPE\_STRING, and etc. For the details, please see [mysql\_types.h](../src/protocol/mysql_types.h).
- `bool is_TYPE() const;` . The TYPE is int, string or ulonglong. It is used to check the data type.
- `TYPE as_TYPE() const;` Same as the above. It reads the data from MySQLCell in a certain type.
- `void get_cell_nocopy(const void **data, size_t *len, int *data_type) const;` nocopy interface.

The whole example is shown below:

~~~cpp
void task_callback(WFMySQLTask *task)
{
    // step-1. 判断任务状态 
    if (task->get_state() != WFT_STATE_SUCCESS)
    {
        fprintf(stderr, "task error = %d\n", task->get_error());
        return;
    }

    MySQLResultCursor cursor(task->get_resp());
    bool test_first_result_set_flag = false;
    bool test_rewind_flag = false;

begin:
    // step-2. 判断回复包状态
    switch (resp->get_packet_type())
    {
    case MYSQL_PACKET_OK:
        fprintf(stderr, "OK. %llu rows affected. %d warnings. insert_id=%llu.\n",
                task->get_resp()->get_affected_rows(),
                task->get_resp()->get_warnings(),
                task->get_resp()->get_last_insert_id());
        break;

    case MYSQL_PACKET_EOF:
        do {
            fprintf(stderr, "cursor_status=%d field_count=%u rows_count=%u ",
                    cursor.get_cursor_status(), cursor.get_field_count(), cursor.get_rows_count());
            // step-3. 判断结果集状态
            if (cursor.get_cursor_status() != MYSQL_STATUS_GET_RESULT)
                break;

            // step-4. 读取每个fields。这是个nocopy api
            const MySQLField *const *fields = cursor.fetch_fields();
            for (int i = 0; i < cursor.get_field_count(); i++)
            {
                fprintf(stderr, "db=%s table=%s name[%s] type[%s]\n",
                        fields[i]->get_db().c_str(), fields[i]->get_table().c_str(),
                        fields[i]->get_name().c_str(), datatype2str(fields[i]->get_data_type()));
            }

            // step-6. 把所有行读出，也可以while (cursor.fetch_row(map/vector)) 按step-5拿每一行
            std::vector<std::vector<MySQLCell>> rows;

            cursor.fetch_all(rows);
            for (unsigned int j = 0; j < rows.size(); j++)
            {
                // step-10. 具体每个cell的读取
                for (unsigned int i = 0; i < rows[j].size(); i++)
                {
                    fprintf(stderr, "[%s][%s]", fields[i]->get_name().c_str(),
                            datatype2str(rows[j][i].get_data_type()));
                    // step-10. 判断具体类型is_string()和转换具体类型as_string()
                    if (rows[j][i].is_string())
                    {
                        std::string res = rows[j][i].as_string();
                        fprintf(stderr, "[%s]\n", res.c_str());
                    } else if (rows[j][i].is_int()) {
                        fprintf(stderr, "[%d]\n", rows[j][i].as_int());
                    } // else if ...
                }
            }
        // step-8. 拿下一个结果集
        } while (cursor.next_result_set());

        if (test_first_result_set_flag == false)
        {
            test_first_result_set_flag = true;
            // step-9. 返回第一个结果集
            cursor.first_result_set();
            goto begin;
        }

        if (test_rewind_flag == false)
        {
            test_rewind_flag = true;
            // step-7. 返回当前结果集头部
            cursor.rewind();
            goto begin;
        }
        break;

    default:
        fprintf(stderr, "Abnormal packet_type=%d\n", resp->get_packet_type());
        break;
    }
    return;
}
~~~

# WFMySQLConnection

Since it is a highly concurrent asynchronous client, this means that the client may have more than one connection to a server. As both MySQL transactions and preparation are stateful, in order to ensure that one transaction or preparation ocupies one connection exclusively, you can use our encapsulated secondary factory WFMySQLConnection to create a task. Each WFMySQLConnection guarantees that one connection  is occupied exclusively. For the details, please see [WFMySQLConnection.h](../src/client/WFMySQLConnection.h).

### 1\. Creating and initializing WFMySQLConnection

When creating a WFMySQLConnection, you need to pass in globally unique **id**, and the framework will use the id to find the corresponding unique connection in subsequent calls.

When initializing a WFMySQLConnection, you need to pass a URL, and then you do not need to set the URL for the task created on this connection.

~~~cpp
class WFMySQLConnection
{
public:
    WFMySQLConnection(int id);
    int init(const std::string& url);
    ...
};
~~~

### 2\. Creating a task and closing a connection

With **create\_query\_task()**, you can create a task by writing an SQL request and a callback function. The task must be sent on this connection.

Sometimes you need to close this connection manually. Because when you stop using it, this connection will be kept until MySQL server times out. During this period, if you use the same id and url to create a WFMySQLConnection, you reuse the connection.

Therefore, we suggest that if you are not ready to reuse the connection, you should use **create\_disconnect\_task()** to create a task and manually close the connection.

~~~cpp
class WFMySQLConnection
{
public:
    ...
    WFMySQLTask *create_query_task(const std::string& query,
                                   mysql_callback_t callback);
    WFMySQLTask *create_disconnect_task(mysql_callback_t callback);
}
~~~

WFMySQLConnection is equivalent to a secondary factory. In the framework, we arrange that the life cycle of any factory object does not need to be maintained until the task ends. The following code is completely legal:

~~~cpp
    WFMySQLConnection *conn = new WFMySQLConnection(1234);
    conn->init(url);
    auto *task = conn->create_query_task("SELECT * from table", my_callback);
    conn->deinit();
    delete conn;
    task->start();
~~~

### 3\. Cautions

If you have started BEGIN but have not COMMIT or ROLLBACK during the transaction and the connection has been interrupted during the transaction, the connection will be automatically reconnected internally by the framework, and you will get **ECONNRESET** error in the next task request. In this case, the transaction statement that is not COMMIT has expired and you need to sent it again.

### 4\. Preparation

You can also use the WFMySQLConnection for **PREPARE**. And you can easily use it to **defend against SQL injection**. If the connection is reconnected, you also get an **ECONNRESET** error.

### 5\. Complete example

~~~cpp
WFMySQLConnection conn(1);
conn.init("mysql://root@127.0.0.1/test");

// test transaction
const char *query = "BEGIN;";
WFMySQLTask *t1 = conn.create_query_task(query, task_callback);
query = "SELECT * FROM check_tiny FOR UPDATE;";
WFMySQLTask *t2 = conn.create_query_task(query, task_callback);
query = "INSERT INTO check_tiny VALUES (8);";
WFMySQLTask *t3 = conn.create_query_task(query, task_callback);
query = "COMMIT;";
WFMySQLTask *t4 = conn.create_query_task(query, task_callback);
WFMySQLTask *t5 = conn.create_disconnect_task(task_callback);
((*t1) > t2 > t3 > t4 > t5).start();
~~~
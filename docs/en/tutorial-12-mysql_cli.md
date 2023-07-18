# Asynchronous MySQL client: mysql\_cli

# Sample code

[tutorial-12-mysql\_cli.cc](/tutorial/tutorial-12-mysql_cli.cc)

# About mysql\_cli

The usage of mysql\_cli in the tutorial is similar to that of the official client. It is an asynchronous MySQL client with an interactive command line interface.

To start the program, run the command: ./mysql_cli \<URL\>

After startup, you can directly enter MySQL command in the terminal to interact with db, or enter `quit` or `Ctrl-C` to exit.

# Format of MySQL URL

mysql://username:password@host:port/dbname?character\_set=charset&character\_set\_results=charset

- set scheme to be **mysqls://** for accessing MySQL with SSL connnection (MySQL server 5.7 or above is required).

- fill in the username and the password for the MySQL database;

- the default port number is 3306;

- **dbname** is the name of the database to be used. It is recommended to provide a dbname if SQL statements only operates on one database;

- If you have upstream selection requirements for MySQL, please see [upstream documents](/docs/en/about-upstream.md).

- **character_set** indicates a character set used for the client, with the same meaning of --default-character-set in official client. The default value is utf8. For details, please see official MySQL documents [character-set.html](https://dev.mysql.com/doc/internals/en/character-set.html).

- **character_set_results** indicates a character set for client, connection and results. If you wants to use `SET NAMES ` in SQL statements, please set it here.

Sample MySQL URL:

mysql://root:password@127.0.0.1

mysql://@test.mysql.com:3306/db1?character\_set=utf8&character_set_results=utf8

mysqls://localhost/db1?character\_set=big5

# Creating and starting a MySQL task

You can use WFTaskFactory to create a MySQL task. The usage of creating interface and callback functions are similar to other tasks in workflow:

~~~cpp
using mysql_callback_t = std::function<void (WFMySQLTask *)>;

WFMySQLTask *create_mysql_task(const std::string& url, int retry_max, mysql_callback_t callback);

void set_query(const std::string& query);
~~~

You can call **set\_query()** on the request to write SQL statements after creating a WFMySQLTask.

If **set_query()** had **NOT** been called before the task started, the user might get **WFT_ERR_MYSQL_QUERY_NOT_SET** in callback.

Other functions, including callback, series and user\_data are used in a way similar to other tasks in workflow.

The following codes show some general usage:
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

Currently the supported command is **COM\_QUERY**, which can cover the basic requirements for adding, deleting, modifying and querying data, creating and deleting databases, creating and deleting tables, prepare, using stored procedures and using transactions.

Because the program doesn't support the selection of databases (**USE** command) in our interactive commands, if there are **cross-database** operations in SQL statements, you can specify the database and table with **db\_name.table\_name**.

Any other command can be **spliced together** and then passed to WFMySQLTask with `set_query()`. (including INSERT/UPDATE/SELECT/PREPARE/CALL)

The spliced commands will be executed sequentially until an error occurs, and the previous commands will be executed successfully.

For example:

~~~cpp
req->set_query("SELECT * FROM table1; CALL procedure1(); INSERT INTO table3 (id) VALUES (1);");
~~~

# Parsing results

Similar to other tasks in workflow, you can use **task->get\_resp()** to get **MySQLResponse**. For details on the interfaces, please see [MySQLResult.h](/src/protocol/MySQLResult.h).

One request will get one response, which is a 3-dimensional structure.
- one response consists of one or more result sets;
- the type of each result set may be **MYSQL_STATUS_GET_RESULT** or **MYSQL_STATUS_OK**;
- one result set of type **MYSQL_STATUS_GET_RESULT** consists of one ore more rows;
- one row consists of one or more fields, or data cells;

The two types of result sets can be judged by ``cursor->get_cursor_status()``.

|      |MYSQL_STATUS_GET_RESULT|MYSQL_STATUS_OK|
|------|-----------------------|---------------|
|SQL command|SELECT(including each SELECT in PROCEDURE)|INSERT / UPDATE / DELETE / ...|
|Semantics|Read. One result set consists of a 2-dimensional structure </br>reprecenting the response of one read operation.|Write. One result set reprecents the results of </br>one write operation.|
|main APIs|fetch_fields();</br>fetch_row(&row_arr);</br>...|get_insert_id();</br>get_affected_rows();</br>...|

When errors occur in spliced commands, you may first get the multiple result sets through **MySQLResultCursor**, the commands which have been executed successfully. Then determine whether ``resp->get_packet_type()`` equals to **MYSQL_PACKET_ERROR** and get the specific error information through ``resp->get_error_code()`` and ``resp->get_error_msg()``.

A **PROCEDURE** command containing N **SELECT** statements will return N result sets of **MYSQL_STATUS_GET_RESULT** and 1 result set of **MYSQL_STATUS_OK**. The user ignores this **MYSQL_STATUS_OK** result set is fine.

To get all the data, the specific steps should be:

1. checking the task state (state at communication): you can check whether the task is successfully executed by checking whether ``task->get_state()`` is equal to **WFT_STATE_SUCCESS**;

2. determining the type of the response packet (state at parsing the return packet): call ``resp->get_packet_type()`` to check the type of the last SQL query return packet. The common types include:

- MYSQL\_PACKET\_OK: parsed successfully, should use cursor to get all the result sets.
- MYSQL\_PACKET\_EOF: parsed successfully, should use cursor to get all the result sets.
- MYSQL\_PACKET\_ERROR: requests: failed or partial failed, may use cursor to get the result sets of those successful commands.

3. traverse the result sets: you can use **MySQLResultCursor** to read the content in the result set. Because the data returned by a MySQL server contains multiple result sets, the cursor will **automatically point to the reading position of the first result set** at first.

4. checking the result set state (state at reading the result sets):   **cursor->get_cursor_status()** returns the following states:

- MYSQL\_STATUS\_GET\_RESULT: current result set is a READ result set;
- MYSQL\_STATUS\_END: the last record of the current READ result set has been read;
- MYSQL\_STATUS\_OK: current result set is a WRITE result set;
- MYSQL\_STATUS\_ERROR: parsing error;

5. reading the basic content of **MYSQL_STATUS_OK** result set:
  - ``unsigned long long get_affected_rows() const;``
  - ``unsigned long long get_insert_id() const;``
  - ``int get_warnings() const;``
  - ``std::string get_info() const;``
  
6. reading each field and each columns of **MYSQL_STATUS_GET_RESULT** result set:
  - `int get_field_count() const;`
  - `const MySQLField *fetch_field();`
  - `const MySQLField *const *fetch_fields() const;`

7. reading each line of **MYSQL_STATUS_GET_RESULT** result set: you can use ``cursor->fetch_row()`` to read by row until the return value is false, in which the offset within the cursor that points to the row in the current result set will be moved:
- `int get_rows_count() const;`
- `bool fetch_row(std::vector<MySQLCell>& row_arr);`
- `bool fetch_row(std::map<std::string, MySQLCell>& row_map);`
- `bool fetch_row(std::unordered_map<std::string, MySQLCell>& row_map);`
- `bool fetch_row_nocopy(const void **data, size_t *len, int *data_type);`

8. taking out all the rows in the current **MYSQL_STATUS_GET_RESULT** result set directly: you can use ``cursor->fetch_all()`` to read all rows, and the cursor that is used to record the rows internally will be moved directly to the end; The cursor state changes to **MYSQL_STATUS_END**:
- `bool fetch_all(std::vector<std::vector<MySQLCell>>& rows);`

9. returning to the head of the current **MYSQL_STATUS_GET_RESULT** result set: if it is necessary to read this result set again, you can use ``cursor->rewind()`` to return to the head of the current result set, and then read it via the operations in Step 7 or Step 8;

10. getting the next result set: because the data packet returned by MySQL server may contains multiple result sets (for example, each SELECT/INSERT/... statement gets one result set; or the multiple result sets returned by calling a PROCEDURE). Therefore, you can use ``cursor->next_result_set()`` to jump to the next result set. If the return value is false, it means that all result sets have been taken.

11. returning to the first result set: use **cursor->first\_result\_set()** to return to the heads of all result sets, and then you can repeat the operations from Step 4.

12. getting the data of each column (MySQLCell): the row read in Step 5 is composed of multiple columns, and the result of each column is one MySQLCell. It mainly uses the following interfaces:

- `int get_data_type();` returns MYSQL\_TYPE\_LONG, MYSQL\_TYPE\_STRING, and etc. For the details, please see [mysql\_types.h](/src/protocol/mysql_types.h).
- `bool is_TYPE() const;` the TYPE is int, string or ulonglong. It is used to check the data type.
- `TYPE as_TYPE() const;` same as the above. It reads the data from MySQLCell in a certain type.
- `void get_cell_nocopy(const void **data, size_t *len, int *data_type) const;` nocopy interface.

The whole example is shown below:

~~~cpp
void task_callback(WFMySQLTask *task)
{
    // step-1. Check the status of the task
    if (task->get_state() != WFT_STATE_SUCCESS)
    {
        fprintf(stderr, "task error = %d\n", task->get_error());
        return;
    }

    MySQLResultCursor cursor(task->get_resp());
    bool test_first_result_set_flag = false;
    bool test_rewind_flag = false;

    // step-2. Check other status of repsponse packet
    if (resp->get_packet_type() == MYSQL_PACKET_ERROR)
    {
        fprintf(stderr, "ERROR. error_code=%d %s\n",
                task->get_resp()->get_error_code(),
                task->get_resp()->get_error_msg().c_str());
    }

begin:
    // step-3. Traverse the result sets
    do {
        // step-4. Check the status of the result set
        if (cursor.get_cursor_status() == MYSQL_STATUS_OK)
        {
            // step-5. Read the basic content of MYSQL_STATUS_OK result set
            fprintf(stderr, "OK. %llu rows affected. %d warnings. insert_id=%llu.\n",
                    cursor.get_affected_rows(), cursor.get_warnings(), cursor.get_insert_id());
        }
        else if (cursor.get_cursor_status() == MYSQL_STATUS_GET_RESULT)
        {
            fprintf(stderr, "field_count=%u rows_count=%u ",
                    cursor.get_field_count(), cursor.get_rows_count());

            // step-6. Read each fields. This is a nocopy api
            const MySQLField *const *fields = cursor.fetch_fields();
            for (int i = 0; i < cursor.get_field_count(); i++)
            {
                fprintf(stderr, "db=%s table=%s name[%s] type[%s]\n",
                        fields[i]->get_db().c_str(), fields[i]->get_table().c_str(),
                        fields[i]->get_name().c_str(), datatype2str(fields[i]->get_data_type()));
            }

            // step-8. Read all the rows. You may use while (cursor.fetch_row(map/vector)) to get each rows accoding to step-7
            std::vector<std::vector<MySQLCell>> rows;

            cursor.fetch_all(rows);
            for (unsigned int j = 0; j < rows.size(); j++)
            {
                // step-12. Read each cell
                for (unsigned int i = 0; i < rows[j].size(); i++)
                {
                    fprintf(stderr, "[%s][%s]", fields[i]->get_name().c_str(),
                            datatype2str(rows[j][i].get_data_type()));
                    // step-12. Check the type wih is_string()and transform the type with as_string()
                    if (rows[j][i].is_string())
                    {
                        std::string res = rows[j][i].as_string();
                        fprintf(stderr, "[%s]\n", res.c_str());
                    }
                    else if (rows[j][i].is_int())
                    {
                        fprintf(stderr, "[%d]\n", rows[j][i].as_int());
                    } // else if ...
                }
            }
        }
    // step-10. Get the next result set
    } while (cursor.next_result_set());

    if (test_first_result_set_flag == false)
    {
        test_first_result_set_flag = true;
        // step-11.  Go back to the first result set
        cursor.first_result_set();
        goto begin;
    }

    if (test_rewind_flag == false)
    {
        test_rewind_flag = true;
        // step-9. Go back to the first position of the current result set
        cursor.rewind();
        goto begin;
    }

    return;
}
~~~

# WFMySQLConnection

Since it is a highly concurrent asynchronous client, this means that the client may have more than one connection to the server. As both MySQL transactions and preparation are stateful, in order to ensure that one transaction or preparation ocupies one connection exclusively, you can use our encapsulated secondary factory WFMySQLConnection to create a task. Each WFMySQLConnection guarantees that one connection is occupied exclusively. For the details, please see [WFMySQLConnection.h](/src/client/WFMySQLConnection.h).

### 1\. Creating and initializing WFMySQLConnection

When creating a WFMySQLConnection, you need to pass in globally unique **id**, and the subsequent calls on this WFMySQLConnection will use this id to find the corresponding unique connection.

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

With **create\_query\_task()**, you can create a task by writing an SQL request and a callback function. The task is garuanteed to be sent on this connection.

Sometimes you need to close this connection manually. Because when you stop using it, this connection will be kept until MySQL server time out. During this period, if you use the same id and url to create a WFMySQLConnection, you may reuse the connection.

Therefore, we suggest that if you do not want to reuse the connection, you should use **create\_disconnect\_task()** to create a task and manually close the connection.

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

If you have started `BEGIN` but have not `COMMIT` or `ROLLBACK` during the transaction and the connection has been interrupted during the transaction, the connection will be automatically reconnected internally by the framework, and you will get **ECONNRESET** error in the next task request. In this case, the transaction statements those have not been `COMMIT` would be expired and you may need to send them again.

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
SeriesWork *series = create_series_work(t1, nullptr);
*series << t2 << t3 << t4 << t5;
series->start();
~~~

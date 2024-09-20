# 异步MySQL客户端：mysql_cli
# 示例代码

[tutorial-12-mysql_cli.cc](/tutorial/tutorial-12-mysql_cli.cc)

# 关于mysql_cli

教程中的mysql_cli使用方式与官方客户端相似，是一个命令行交互式的异步MySQL客户端。

程序运行方式：./mysql_cli \<URL\>

启动之后可以直接在终端输入mysql命令与db进行交互，输入quit或Ctrl-C退出。

# MySQL URL的格式

mysql://username:password@host:port/dbname?character_set=charset&character_set_results=charset

- 如果以SSL连接访问MySQL，则scheme设为**mysqls://**。MySQL server 5.7及以上支持；

- username和password按需填写，如果密码里包含特殊字符，需要转义后再拼接URL；
~~~cpp
// 密码为：@@@@####
std::string url = "mysql://root:" + StringUtil::url_encode_component("@@@@####") + "@127.0.0.1";
~~~
- port默认为3306；

- dbname为要用的数据库名，一般如果SQL语句只操作一个db的话建议填写；

- 如果用户在这一层有upstream选取需求，可以参考[upstream文档](/docs/about-upstream.md)；

- character_set为client的字符集，等价于使用官方客户端启动时的参数``--default-character-set``的配置，默认utf8，具体可以参考MySQL官方文档[character-set.html](https://dev.mysql.com/doc/internals/en/character-set.html)。

- character_set_results为client、connection和results的字符集，如果想要在SQL语句里使用``SET NAME``来指定这些字符集的话，请把它配置到url的这个位置。

MySQL URL示例：

mysql://root:password@127.0.0.1

mysql://@test.mysql.com:3306/db1?character_set=utf8&character_set_results=utf8

mysqls://localhost/db1?character\_set=big5

# 创建并启动MySQL任务

用户可以使用WFTaskFactory创建MySQL任务，创建接口与回调函数的用法都与workflow其他任务类似:
~~~cpp
using mysql_callback_t = std::function<void (WFMySQLTask *)>;

WFMySQLTask *create_mysql_task(const std::string& url, int retry_max, mysql_callback_t callback);

void set_query(const std::string& query);
~~~
用户创建完WFMySQLTask之后，可以对req调用 **set_query()** 写入SQL语句。

如果没调用过 **set_query()** ，task就被start起来的话，则用户会在callback里得到**WFT_ERR_MYSQL_QUERY_NOT_SET**。

其他包括callback、series、user_data等与workflow其他task用法类似。

大致使用示例如下：
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

# 支持的命令

目前支持的命令为**COM_QUERY**，已经能涵盖用户基本的增删改查、建库删库、建表删表、预处理、使用存储过程和使用事务的需求。

因为我们的交互命令中不支持选库（**USE**命令），所以，如果SQL语句中有涉及到**跨库**的操作，则可以通过**db_name.table_name**的方式指定具体哪个库的哪张表。

其他所有命令都可以**拼接**到一起通过 ``set_query()`` 传给WFMySQLTask（包括INSERT/UPDATE/SELECT/DELETE/PREPARE/CALL）。

拼接的命令会被按序执行直到命令发生错误，前面的命令会执行成功。

举个例子：
~~~cpp
req->set_query("SELECT * FROM table1; CALL procedure1(); INSERT INTO table3 (id) VALUES (1);");
~~~

# 结果解析

与workflow其他任务类似，可以用``task->get_resp()``拿到**MySQLResponse**，我们可以通过**MySQLResultCursor**遍历结果集。具体接口可以查看：[MySQLResult.h](/src/protocol/MySQLResult.h)

一次请求所对应的回复中，其数据是一个三维结构：
- 一个回复中包含了一个或多个结果集（result set）；
- 一个结果集的类型可能是**MYSQL_STATUS_GET_RESULT**或者**MYSQL_STATUS_OK**；
- **MYSQL_STATUS_GET_RESULT**类型的结果集包含了一行或多行（row）；
- 一行包含了一列或多个列，或者说一到多个阈（Field/Cell），具体数据结构为**MySQLField**和**MySQLCell**；

结果集的两种类型，可以通过``cursor->get_cursor_status()``进行判断：

|      |MYSQL_STATUS_GET_RESULT|MYSQL_STATUS_OK|
|------|-----------------------|---------------|
|SQL命令|SELECT（包括存储过程中的每一个SELECT）|INSERT / UPDATE / DELETE / ...|
|对应语义|读操作，一个结果集表示一份读操作返回的二维表|写操作，一个结果集表示一个写操作是否成功|
|主要接口|fetch_fields();</br>fetch_row(&row_arr);</br>...|get_insert_id();</br>get_affected_rows();</br>...|

由于拼接语句可能存在错误，因此这种情况，可以通过**MySQLResultCursor**拿到前面正确执行过的语句多个结果集，以及最后判断``resp->get_packet_type()``为**MYSQL_PACKET_ERROR**时，通过``resp->get_error_code()``和``resp->get_error_msg()``拿到具体错误信息。

一个包含n条**SELECT**语句的**存储过程**，会返回n个**MYSQL_STATUS_GET_RESULT**的结果集和1个**MYSQL_STATUS_OK**的结果集，用户自行忽略此**MYSQL_STATUS_OK**结果集即可。

具体使用从外到内的步骤应该是：

1. 判断任务状态（代表通信层面状态）：用户通过判断 ``task->get_state()`` 等于**WFT_STATE_SUCCESS**来查看任务执行是否成功；

2. 判断回复包类型（代表返回包解析状态）：调用 **resp->get_packet_type()** 查看最后一条MySQL语句的返回包类型，常见的几个类型为：
  - MYSQL_PACKET_OK：成功，可以用cursor遍历结果；
  - MYSQL_PACKET_EOF：成功，可以用cursor遍历结果；
  - MYSQL_PACKET_ERROR：失败或部分失败，成功的部分可以用cursor遍历结果；

3. 遍历结果集。用户可以使用**MySQLResultCursor**读取结果集中的内容，因为MySQL server返回的数据是多结果集的，因此一开始cursor会**自动指向第一个结果集**的读取位置。

4. 判断结果集状态（代表结果集读取状态）：通过 ``cursor->get_cursor_status()`` 可以拿到的几种状态：
  - MYSQL_STATUS_GET_RESULT：此结果集为读请求类型；
  - MYSQL_STATUS_END：读结果集已读完最后一行；
  - MYSQL_STATUS_OK：此结果集为写请求类型；
  - MYSQL_STATUS_ERROR：解析错误；

5. 读取**MYSQL_STATUS_OK**结果集中的基本内容：
  - ``unsigned long long get_affected_rows() const;``
  - ``unsigned long long get_insert_id() const;``
  - ``int get_warnings() const;``
  - ``std::string get_info() const;``

6. 读取**MYSQL_STATUS_GET_RESULT**结果集中的columns中每个field：
  - ``int get_field_count() const;``
  - ``const MySQLField *fetch_field();``
    - ``const MySQLField *const *fetch_fields() const;``

7. 读取**MYSQL_STATUS_GET_RESULT**结果集中的每一行：按行读取可以使用 ``cursor->fetch_row()`` 直到返回值为false。其中会移动cursor内部对当前结果集的指向每行的offset：
  - ``int get_rows_count() const;``
  - ``bool fetch_row(std::vector<MySQLCell>& row_arr);``
  - ``bool fetch_row(std::map<std::string, MySQLCell>& row_map);``
  - ``bool fetch_row(std::unordered_map<std::string, MySQLCell>& row_map);``
  - ``bool fetch_row_nocopy(const void **data, size_t *len, int *data_type);``

8. 直接把当前**MYSQL_STATUS_GET_RESULT**结果集的所有行拿出：所有行的读取可以使用 **cursor->fetch_all()** ，内部用来记录行的cursor会直接移动到最后；当前cursor状态会变成**MYSQL_STATUS_END**：
  - ``bool fetch_all(std::vector<std::vector<MySQLCell>>& rows);``

9. 返回当前**MYSQL_STATUS_GET_RESULT**结果集的头部：如果有必要重读这个结果集，可以使用 **cursor->rewind()** 回到当前结果集头部，再通过第7步或第8步进行读取；

10. 拿到下一个结果集：因为MySQL server返回的数据包可能是包含多结果集的（比如每个select/insert/...语句为一个结果集；或者call procedure返回的多结果集数据），因此用户可以通过 **cursor->next_result_set()** 跳到下一个结果集，返回值为false表示所有结果集已取完。

11. 返回第一个结果集：**cursor->first_result_set()** 可以让我们返回到所有结果集的头部，然后可以从第4步开始重新拿数据；

12. **MYSQL_STATUS_GET_RESULT**结果集每列具体数据MySQLCell：第7步中读取到的一行，由多列组成，每列结果为MySQLCell，基本使用接口有：
  - ``int get_data_type();`` 返回MYSQL_TYPE_LONG、MYSQL_TYPE_STRING...具体参考[mysql_types.h](/src/protocol/mysql_types.h)
  - ``bool is_TYPE() const;`` TYPE为int、string、ulonglong，判断是否是某种类型
  - ``TYPE as_TYPE() const;`` 同上，以某种类型读出MySQLCell的数据
  - ``void get_cell_nocopy(const void **data, size_t *len, int *data_type) const;`` nocopy接口

整体示例如下：
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

    // step-2. 判断回复包其他状态
    if (resp->get_packet_type() == MYSQL_PACKET_ERROR)
    {
        fprintf(stderr, "ERROR. error_code=%d %s\n",
                task->get_resp()->get_error_code(),
                task->get_resp()->get_error_msg().c_str());
    }

begin:
    // step-3. 遍历结果集
    do {
        // step-4. 判断结果集状态
        if (cursor.get_cursor_status() == MYSQL_STATUS_OK)
        {
            // step-5. MYSQL_STATUS_OK结果集的基本内容
            fprintf(stderr, "OK. %llu rows affected. %d warnings. insert_id=%llu.\n",
                    cursor.get_affected_rows(), cursor.get_warnings(), cursor.get_insert_id());
        }
        else if (cursor.get_cursor_status() == MYSQL_STATUS_GET_RESULT)
        {
            fprintf(stderr, "field_count=%u rows_count=%u ",
                    cursor.get_field_count(), cursor.get_rows_count());

            // step-6. 读取每个fields。这是个nocopy api
            const MySQLField *const *fields = cursor.fetch_fields();
            for (int i = 0; i < cursor.get_field_count(); i++)
            {
                fprintf(stderr, "db=%s table=%s name[%s] type[%s]\n",
                        fields[i]->get_db().c_str(), fields[i]->get_table().c_str(),
                        fields[i]->get_name().c_str(), datatype2str(fields[i]->get_data_type()));
            }

            // step-8. 把所有行读出，也可以while (cursor.fetch_row(map/vector)) 按step-7拿每一行
            std::vector<std::vector<MySQLCell>> rows;

            cursor.fetch_all(rows);
            for (unsigned int j = 0; j < rows.size(); j++)
            {
                // step-12. 具体每个cell的读取
                for (unsigned int i = 0; i < rows[j].size(); i++)
                {
                    fprintf(stderr, "[%s][%s]", fields[i]->get_name().c_str(),
                            datatype2str(rows[j][i].get_data_type()));
                    // step-12. 判断具体类型is_string()和转换具体类型as_string()
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
    // step-10. 拿下一个结果集
    } while (cursor.next_result_set());

    if (test_first_result_set_flag == false)
    {
        test_first_result_set_flag = true;
        // step-11. 返回第一个结果集
        cursor.first_result_set();
        goto begin;
    }

    if (test_rewind_flag == false)
    {
        test_rewind_flag = true;
        // step-9. 返回当前结果集头部
        cursor.rewind();
        goto begin;
    }

    return;
}
~~~

# WFMySQLConnection

由于我们是高并发异步客户端，这意味着我们对一个server的连接可能会不止一个。而MySQL的事务和预处理都是带状态的，为了保证一次事务或预处理独占一个连接，用户可以使用我们封装的二级工厂WFMySQLConnection来创建任务，每个WFMySQLConnection保证独占一个连接，具体参考[WFMySQLConnection.h](/src/client/WFMySQLConnection.h)。

### 1. WFMySQLConnection的创建与初始化

创建一个WFMySQLConnection的时候需要传入一个**id**，之后的调用内部都会由这个id和url去找到对应的那个连接。

初始化需要传入**url**，之后在这个connection上创建的任务就不需要再设置url了。

~~~cpp
class WFMySQLConnection
{
public:
    WFMySQLConnection(int id);
    int init(const std::string& url);
    ...
};
~~~

### 2. 创建任务与关闭连接

通过 **create_query_task()** ，写入SQL请求和回调函数即可创建任务，该任务一定从这一个connection发出。

有时候我们需要手动关闭这个连接。因为当我们不再使用它的时候，这个连接会一直保持到MySQL server超时。期间如果使用同一个id和url去创建WFMySQLConnection的话就可以复用到这个连接。

因此我们建议如果不准备复用连接，应使用 **create_disconnect_task()** 创建一个任务，手动关闭这个连接。
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
WFMySQLConnection相当于一个二级工厂，我们约定任何工厂对象的生命周期无需保持到任务结束，以下代码完全合法：
~~~cpp
    WFMySQLConnection *conn = new WFMySQLConnection(1234);
    conn->init(url);
    auto *task = conn->create_query_task("SELECT * from table", my_callback);
    conn->deinit();
    delete conn;
    task->start();
~~~

### 3. 注意事项

不可以无限制的产生id来生成连接对象，因为每个id会占用一小块内存，无限产生id会使内存不断增加。当一个连接使用完毕，可以不创建和运行disconnect task，而是让这个连接进入内部连接池。下一个connection通过相同的id和url初始化，会自动复用这个连接。

同一个连接上的多个任务并行启动，会得到EAGAIN错误。

如果在使用事务期间已经开始BEGIN但还没有COMMIT或ROLLBACK，且期间连接发生过中断，则连接会被框架内部自动重连，用户会在下一个task请求中拿到**ECONNRESET**错误。此时还没COMMIT的事务语句已经失效，需要重新再发一遍。

### 4. 预处理

用户也可以通过WFMySQLConnection来做预处理**PREPARE**，因此用户可以很方便地用作**防SQL注入**。如果连接发生了重连，也会得到一个**ECONNRESET**错误。

### 5. 完整示例

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


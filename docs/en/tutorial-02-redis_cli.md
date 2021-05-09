# Implementing Redis set and get: redis\_cli

# Sample code

[tutorial-02-redis\_cli.cc](/tutorial/tutorial-02-redis_cli.cc)

# About redis\_cli

The program reads the Redis server address and a key/value pair from the command line. Then execute SET to write this KV pair and then read them to verify that the writing is sucessful.   
Command: ./redis_cli \<redis URL\> \<key\> \<value\>   
For the sake of simplicity, press Ctrl-C to exit the program.

# Format of Redis URL

redis://:password@host:port/dbnum?query#fragment   
If SSL is used, use:   
rediss://:password@host:port/dbnum?query#fragment   
password is optional. The default port is 6379; the default dbnum is 0, and its range is from 0 to 15.   
query and fragment are not used in the factory and you can define them by yourself. For example, if you want to use upstream selection , you can define your own query and fragment. For relevant details, please see upstream documents.   
Sample Redis URL:   
redis://127.0.0.1/  
redis://:12345678@redis.some-host.com/1

# Creating and starting a Redis task

Creating a Redis task is almost the same as creating an HTTP task. The only difference is the omission of redirect\_max.

~~~cpp
using redis_callback_t = std::function<void (WFRedisTask *)>;

WFRedisTask *create_redis_task(const std::string& url,
                               int retry_max,
                               redis_callback_t callback);
~~~

In this example, we want to store some user data in the Redis task, including URL and key, and use them in the callback.   
We can use **std::function** to bind the parameters. Here we use **void \*user\_data** pointer in the task. The pointer is a public member of the task.

~~~cpp
struct tutorial_task_data
{
    std::sring url;
    std::string key;
};
...
struct tutorial_task_data data;
data.url = argv[1];
data.key = argv[2];

WFRedisTask *task = WFTaskFactory::create_redis_task(data.url, RETRY_MAX, redis_callback);

protocol::RedisRequest *req = task->get_req();
req->set_request("SET", { data.key, argv[3] });

task->user_data = &data;
task->start();
pause();
~~~

Similar to **get\_req()** in an HTTP task, **get\_req()** in an Redis task returns the Redis request for that task.
You can see the functions of RedisRequest in [RedisMessage.h](/src/protocol/RedisMessage.h), where **set\_request** is used to set Redis command.

~~~cpp
void set_request(const std::string& command, const std::vector<std::string>& params);
~~~

There is little doubt about this interface for people who frequently use Redis. However, please note that you cannot use SELECT and AUTH commands in the request.   
The reason is that as you can't specify the connection every time you send a request and the next request after SELECT may not be initiated on the same connection, this command is meaningless.   
Please specify the database name and password in the Redis URL. And the URL of every request must contain these data.  
In addition, this redis client fully supports redis cluster mode. The client will process MOVED and ASK response, and redirect correctly.  

# Handling results

After you successfully run the SET command, send the GET command to verify the writing. GET also uses the same callback. Therefore, the function will determine the source command of the results.   
Let's skip the error handling first again.

~~~cpp
void redis_callback(WFRedisTask *task)
{
    protocol::RedisRequest *req = task->get_req();
    protocol::RedisResponse *resp = task->get_resp();
    int state = task->get_state();
    int error = task->get_error();
    protocol::RedisValue val;

    ...
    resp->get_result(val);
    std::string cmd;
    req->get_command(cmd);
    if (cmd == "SET")
    {
        tutorial_task_data *data = (tutorial_task_data *)task->user_data;
        WFRedisTask *next = WFTaskFactory::create_redis_task(data->url, RETRY_MAX, redis_callback);

        next->get_req()->set_request("GET", { data->key });
        series_of(task)->push_back(next);
        fprintf(stderr, "Redis SET request success. Trying to GET...\n");
    }
    else /* if (cmd == 'GET') */
    {
        // print the GET result
        ...
        fprintf(stderr, "Finished. Press Ctrl-C to exit.\n");
    }
}
~~~

RedisValue is the results of one Redis request. You can also see the interface in [RedisMessage.h](/src/protocol/RedisMessage.h).   
You need to pay special attention to the callback in the line **series\_of(task)->push\_back(next)**. It`s the firt time we use the functions of Workflow.   
Here **next** means the Redis task we are about to start: run GET operation. We do not use **next->start()** to start the task. We use **push\_back** to append the next task to the end of the current task queue instead.   
The difference between the two methods is:

* When a task is initiated by **start**, the task is started immediately; when a task is **push\_back** to the queue, the **next** task is initiated after the callback.
  * The obvious advantage is that the **push\_back** method can ensure that the log printing is not chaotic. Otherwise, if you use the **next->start()**, the \"Finished.\" in the sample may be printed out first.
* If you use **start** to initiate the next task, the current task series ends and the next task will initiate a new series.
  * You can set a callback for a series. For the sake of simplicity, the sample omit it.
  * In the parallel tasks, a series is a branch of the parallel task. If the series ends, it is considered that the brand also ends. The following tutorials demonstrates how to use parallel tasks.

In a word, if you want to start the next task after one task, you usually use **push\_back** operation (in some cases, **push\_front** may be used).   
**series\_of()** is a very important call and it is a global function that does not belong to any class. [Workflow.h](/src/factory/Workflow.h#L140) contains its definition and implementation.

~~~cpp
static inline SeriesWork *series_of(const SubTask *task)
{
    return (SeriesWork *)task->get_pointer();
}
~~~

All tasks are derived from SubTask. And any running task must belong to one series. You can call **series\_of()** to get the series of a task.   
**push\_back** is a function in the SeriesWork class, which is used to append a task to the end of the series. **push\_front** is a similar function. In the sample, you can use either function.

~~~cpp
class SeriesWork
{
    ...
public:
    void push_back(SubTask *task);
    void push_front(SubTask *task);
    ...
}
~~~

SeriesWork class plays an important role in our system. In the next tutorial, you will learn more functions in SeriesWork.

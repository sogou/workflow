# More features about series: wget\_to\_redis

# Sample code

[tutorial-03-wget\_to\_redis.cc](/tutorial/tutorial-03-wget_to_redis.cc)

# About wget\_to\_redis

The program reads one HTTP URL and one redis URL from the command line, crawls the HTTP web page and saves the content to Redis, with the key as the HTTP URL.   
Differing from the other two examples, we add a wake-up mechanism. The program can automatically exit and users are not required to press Ctrl-C.

# Creating and configuring an HTTP task

Similar to the previous example, in this example, we also executes two requests in series. The biggest difference is that we inform the main thread that the execution of the task has finished and quit normally.   
In addition, we add two more calls to limit the size of the crawled HTTP response content and the maximum time to receive the reply.

~~~cpp
WFHttpTask *http_task = WFTaskFactory::create_http_task(...);
...
http_task->get_resp()->set_size_limit(20 * 1024 * 1024);
http_task->set_receive_timeout(30 * 1000);
~~~

**set\_size\_limit()** is a function in HttpMessage.It is used to limit the packet size of incoming HTTP message. Actually this interface is required in all protocol messages.   
**set\_receive\_timeout()** sets the timeout for receiving data, in milliseconds.   
The above code limits the size of the HTTP message to no more than 20M and the time for receiving the complete message to no more than 30 seconds. You can learn more about timeout configuration in the following documents.

# Creating and starting a SeriesWork

In the previous two examples, we call **task->start()** directly to start the first task. The actual procedure in **task->start()** is:   
create a SeriesWork with the task as the head and then start the series. In [WFTask.h](/src/factory/WFTask.h), you can see the implemetation of **start**.

~~~cpp
template<class REQ, class RESP>
class WFNetWorkTask : public CommRequest
{
public:
    void start()
    {
        assert(!series_of(this));
        Workflow::start_series_work(this, nullptr);
    }
    ...
};
~~~

We want to set a callback for that series and add some context. Therefore, instead of using the **start** interface of the task, we create our own series.   
You cannot new, delete or inherit a SeriesWork. It can only be generated through  **Workflow::create\_series\_work()** interface. In [Workflow.h](/src/factory/Workflow.h), 
generally we use the following call:

~~~cpp
using series_callback_t = std::function<void (const SeriesWork *)>;

class Workflow
{
public:
    static SeriesWork *create_series_work(SubTask *first, series_callback_t callback);
};
~~~

In the sample code, our usage is as follows:

~~~cpp
struct tutorial_series_context
{
    std::string http_url;
    std::string redis_url;
    size_t body_len;
    bool success;
};
...
struct tutorial_series_context context;
...
SeriesWork *series = Workflow::create_series_work(http_task, series_callback);
series->set_context(&context);
series->start();
~~~

In the previous example, we use the pointer **void \*user\_data** in the task to save the context. However, in this example, we put the context in the series, which is more reasonable. The series is a complete task chain, and all tasks can obtain and modify the context.   
The callback function of the series is called after all the tasks in that series are finished. Here, we simply use a lamda function to print the running results and wake up the main thread.

# Other work

There's nothing special left. After the HTTP crawling is successful, a Redis task is started to write the data into the database. If the crawling fails or the length of the HTTP body is 0, the Redis task will not be started.   
In any case, the program can exit normally after all tasks are finished, because all tasks are in the same series.

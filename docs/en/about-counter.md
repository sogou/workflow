# About counter

Counters are very important basic tasks in our framework. A counter is essentially a semaphore that does not occupy thread.   
Counters are mainly used for workflow control. It includes anonymous counters and named counters, and can realize very complex business logic.

# Creating a counter

As a counter is also a task, it is created through WFTaskFactory. You can create a counter with one of the following two methods:

~~~cpp
using counter_callback_t = std::function<void (WFCounterTask *)>;

class WFTaskFactory
{
    ...
    static WFCounterTask *create_counter_task(unsigned int target_value,
                                              counter_callback_t callback);
                                              
    static WFCounterTask *create_counter_task(const std::string& counter_name,
                                              unsigned int target_value,
                                              counter_callback_t callback);

    ...
};
~~~

Each counter contains a target\_value. When the count in the counter reaches the target\_value, its callback is called.   
The above two interfaces generate a anonymous counter and a named counter respectively. The anonymous counter directly increases the count through the count method in the WFCounterTask:

~~~cpp
class WFCounterTask
{
public:
    virtual void count()
    {
        ...
    }
    ...
}
~~~

If a counter\_name is passed when you create a counter, a named counter is generated, and the count can be increased with the count\_by\_name function.

# Creating parallel tasks with anonymous counters

In the example of [parallel wget](/docs/en/tutorial-06-parallel_wget.md), we created a ParallelWork to achieve the parallel execution of several series.   
With the combination of ParallelWork and SeriesWork, you can build series-parallel graphs in any form, which can meet the requirements in most scenarios.   
Counters allow us to build more complex dependencies between the tasks, such as a fully connected neural network.   
The following simple code can replace ParallelWork to realize parallel HTTP crawling.

~~~cpp
void http_callback(WFHttpTask *task)
{
    /* Save http page. */
    ...

    WFCounterTask *counter = (WFCounterTask *)task->user_data;
    counter->count();
}

std::mutex mutex;
std::condition_variable cond;
bool finished = false;

void counter_callback(WFCounterTask *counter)
{
    mutex.lock();
    finished = true;
    cond.notify_one();
    mutex.unlock();
}

int main(int argc, char *argv[])
{
    WFCounterTask *counter = create_counter_task(url_count, counter_callback);
    WFHttpTask *task;
    std::string url[url_count];

    /* init urls */
    ...

    for (int i = 0; i < url_count; i++)
    {
        task = create_http_task(url[i], http_callback);
        task->user_data = counter;
        task->start();
    }

    counter->start();
    std::unique_lock<std:mutex> lock(mutex);
    while (!finished)   
        cond.wait(lock);
    lock.unlock();
    return 0;
}
~~~

The above code creates a counter with the target value as url\_count, and calls the count once after each HTTP task is completed.   
Note that the times **count()** a anonymous counter cannot exceed it's target value. Otherwise the counter may have been destroyed after the callback, and the program behavior is undefined.   
The call of **counter->start()** can be placed before the for loop. After a counter is created, you can call its count interface, no matter whether the counter has been started or not.   
You can also use **counter->WFCounterTask::count()** to call the count interface of an anonymous counter; this can be used in performance-sensitive applications.

# Using a server together with other asynchronous engines

In some cases, our server may need to call asynchronous clients in other frameworks and wait for the results. A simple method is that we wait synchronously in the process and then are waken up through conditional variables.   
Its disadvantage is that we occupy a processing thread and turn asynchronous clients in other frameworks into synchronous clients. But with the counter method, we can wait without occupying threads. The method is very simple:

~~~cpp

void some_callback(void *context)
{
    protocol::HttpResponse *resp = get_resp_from_context(context);
    WFCounterTask *counter = get_counter_from_context(context);
    /* write data to resp. */
    ...
    counter->count();
}

void process(WFHttpTask *task)
{
    WFCounterTask *counter = WFTaskFactory::create_counter_task(1, nullptr);

    SomeOtherAsyncClient client(some_callback, context);

    *series_of(task) << counter;
}
~~~

Here, we can consider the series of a server task as a coroutine, and the counter whose target value is 1 can be considered as a conditional variable.

# Named counters

When the count operation is executed on the anonymous counter, the counter object pointer is directly accessed. This inevitably requires that the number of calls to count should not exceed the target value during operation.   
But imagine an application scenario where we start four tasks at the same time, and as long as any three tasks are completed, the workflow can continue.   
We can use a counter with a target value of 3, and count once after each task is completed. As long as three tasks are completed, the callback of the counter will be executed.   
But the problem is that when the fourth task is finished and **counter->count()** is called again, the counter is already a wild pointer and the program crashes.   
In this case, we can use named counters to solve this problem. By naming the counter and counting by name, we can have the following implementation:

~~~cpp
void counter_callback(WFCounterTask *counter)
{
    WFRedisTask *next = WFTaskFactory::create_redis_task(...);
    series_of(counter)->push_back(next);
}

int main(void)
{
    WFHttpTask *tasks[4];
    WFCounterTask *counter;

    counter = WFTaskFactory::create_counter_task("c1", 3, counter_callback);
    counter->start();

    for (int i = 0; i < 4; i++)
    {
        tasks[i] = WFTaskFactory::create_http_task(..., [](WFHttpTask *task){
                                            WFTaskFactory::count_by_name("c1"); });
        tasks[i]->start();
    }

    ...

}
~~~

In this example, four concurrent HTTP tasks are started, three of which are completed, and a Redis task is started immediately. In the practical application, you may need to add the code of data transmission.   
In the example, a counter named "c1" is created, and in the HTTP callback, call **WFTaskFactory::count\_by\_name()** to increase the count.

~~~cpp
class WFTaskFactory
{
    ...
    static int count_by_name(const std::string& counter_name);

    static int count_by_name(const std::string& counter_name, unsigned int n);
    ...
};
~~~

You can pass an integer n to **WFTaskFactory::count\_by\_name**, indicating the count value to be increased in this operation. Obviously:   
**count\_by\_name("c1")** is equivalent to **count\_by\_name("c1", 1)**.   
If the "c1" counter does not exist (not created or already completed), the operation on "c1" will have no effect, so the wild pointer problem in an anonymous counter will not happen here.  
The **count\_by\_name()** function returns the number of counters that was waked up by the operation. When **n** is greater that 1, more than one counter may reach target value.

# Definition of the detailed behaviors of named counters

When you **call WFTaskFactory::count\_by\_name(name, n)**:

* if the name does not exist (not created or already completed), there is no action.
* if there is only one counter with that name:
  * if the remaining value of the counter is less than or equal to n, the counting is completed, the callback is called, and the counter is destroyed. end.
  * if the remaining value of the counter is greater than n, the count value is increased by n. end.
* if there are multiple counters with that name:
  * according to the order of creation, take the first counter and assume that its remaining value is m:
    * if m is greater than n, the count value is increased by n. end (the remaining value is m-n).
    * if m is less than or equal to n, the counting is completed, the callback is called, and the counter is destroyed. set n = n-m.
      * If n is 0, the procedure ends.
      * If n is greater than 0, take out the next counter with the same name and repeat the whole operation.

Although the description is very complicated, it can be summed up in one sentence. Access all counters with that name according to the order of creation one by one until n is 0.   
In other words, one **count\_by\_name(name, n)** may wake up multiple counters.   
The counters can be used to realize very complex business logic if you can use them well. In our framework, counters are often used to implement asynchronous locks or to build channels between tasks. It is more like a control task in form.

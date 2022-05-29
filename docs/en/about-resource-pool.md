# Conditional task and resource pool
When we use workflow to write asynchronous programs, we often encounter such scenarios:
* A task needs to obtain a resource from a certain pool before running, and put it back to the pool after it finishs.
* We may need to limit the max concurrency of accessing one or more communication targets. But don't want to occupy a thread when waiting.
* We have many tasks that arrive randomly, in different series. But these tasks must be run serially.

All these needs can be solved with the resource pool module. Our [WFDnsResolver](https://github.com/sogou/workflow/blob/master/src/nameservice/WFDnsResolver.cc) uses this method to control the concurrency of querying the dns server.

# Interfaces of resource pool

In [WFResourcePool.h](https://github.com/sogou/workflow/blob/master/src/factory/WFResourcePool.h) we define the interfaces of resource pool:
~~~cpp
class WFResourcePool
{
public:
    WFConditional *get(SubTask *task, void **resbuf);
    WFConditional *get(SubTask *task);
    void post(void *res);
    ...

protected:
    virtual void *pop()
    {
        return this->data.res[this->data.index++];
    }

    virtual void push(void *res)
    {
        this->data.res[--this->data.index] = res;
    }
    ...

public:
    WFResourcePool(void *const *res, size_t n);
    WFResourcePool(size_t n);
    ...
};
~~~
### Constructors
The first constructor accept a resource array, with the lenght n. Each element of the array is a **void \*** representing a resource. The whole array will be copied by the constructor.  
If all the initial resources are **nullptr**, you may use the second constructor which has only one argument n, representing the number of resources.  
You may take a look of the implementation codes:
~~~cpp
void WFResourcePool::create(size_t n)
{
    this->data.res = new void *[n];
    this->data.value = n;
    ...
}

WFResourcePool::WFResourcePool(void *const *res, size_t n)
{
    this->create(n);
    memcpy(this->data.res, res, n * sizeof (void *));
}

WFResourcePool::WFResourcePool(size_t n)
{
    this->create(n);
    memset(this->data.res, 0, n * sizeof (void *));
}
~~~

### Application interfaces
Users use **get()** method of resource pool to wrap a task. **get()** returns a conditional, which is also a task. Conditional will runs the task it wrap when it obtain a resource from the pool. **get()** may accept a second argument **void \*\* resbuf**, which is the buffer that will store the resource abtained. After the **get()** operation, users can use the returned conditional to substain the original task. It can be started or put to any series just like an ordinary task.  
After the user task is finished, **post()** need to be called to return a resource to the pool. Typically, **post()** is called in user task's callback.

### Derivation
The using of resource pool is FILO. It means the last released resource will be the next one to be obtained. You may subclass WFResourcePool to implement a FIFO pool.

### Example
We have a URL list to be crawled. But we limit the max concurreny of crawling task to be **max_p**. We may use ParallelWork to implement this function of course. But with resource pool, everything is much simpler:
~~~cpp
int fetch_with_max(std::vector<std::string>& url_list, size_t max_p)
{
    WFResourcePool pool(max_p);

    for (std::string& url : url_list)
    {
        WFHttpTask *task = WFTaskFactory::create_http_task(url, [&pool](WFHttpTask *task) {
            pool.post(nullptr);
        });
        WFConditional *cond = pool.get(task);
        cond->start();
    }

    // wait_here...
}
~~~

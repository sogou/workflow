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

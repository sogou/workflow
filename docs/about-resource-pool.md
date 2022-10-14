# 资源池

在我们用workflow写异步程序时经常会遇到这样一些场景：
* 任务运行时需要先从某个池子里获得一个资源。任务运行结束，则会把资源放回池子，让下一个需要资源的任务运行。
* 网络通信时需要对某一个或一些通信目标做总的并发度限制，但又不希望占用线程等待。
* 我们有许多随机到达的任务，处在不同的series里。但这些任务必须**串行**的运行。

所有这些需求，都可以用资源池模块来解决。我们的[WFDnsResolver](https://github.com/sogou/workflow/blob/master/src/nameservice/WFDnsResolver.cc)就是通过这个方法来实现对dns server的并发度控制的。

# 资源池的接口
在[WFResourcePool.h](https://github.com/sogou/workflow/blob/master/src/factory/WFResourcePool.h)里，定义了资源池模块的接口：
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
#### 构造函数
第一个构造函数接受一个资源数组，长度为n。数组每个元素为一个void \*。内部会再分配一份相同大小的内存，把数组复制走。  
如果你的初始资源都是nullptr，那么你可以使用第二个构造函数，只需要传n，而无需先建立一个全部为nullptr的指针数组。  
大概看看内部实现就明白了：
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

#### 使用接口
用户使用get()接口，把任务打包成一个conditional。conditional是一个条件任务，条件满足时运行其包装的任务。  
get()接口可包含第二个参数是一个void \*\*resbuf，用于保存所获得的资源。  
接下来，用户只需要用这个conditional取代原来的任务使用就好了，可以start或串进任务流。  
注意conditional是在它被执行时去尝试获得资源的，而不是在它被创建的时候。要不然的话，以下代码就会被卡死：
~~~cpp
WFResourcePool pool(1);

int f()
{
    WFHttpTask *t1 = WFTaskFactory::create_http_task(..., [](void *){pool.post(nullptr);});
    WFHttpTask *t2 = WFTaskFactory::create_http_task(..., [](void *){pool.post(nullptr);});

    WFConditional *c1 = pool.get(t1, &t1->user_data);  // 用user_data来保存res是一种实用方法。
    WFConditional *c2 = pool.get(t2, &t2->user_data);

    c2->start();
    // wait for t2 finish here.
    ...
    c1->start();
    ...
}
~~~
以上代码c1先创建，等待t2结束后才运行。这里并不会出现c2卡死，因为conditional是在执行时才获得资源的。  
当用户对资源使用完毕（一般在任务callback里），需要通过post()接口把资源放回池子。  
post()时的res参数，**无需**与get()得到res的一致。  

#### 派生
从上面的pop()和push()函数我们可以看到，我们对资源的使用默认是FILO，即先进后出的。  
使用FILO的原因是，大多数场景下，刚刚被释放的资源应该优先被复用。  
但是，用户可以通过派生的方式，非常简单的实现一个FIFO资源池。只需要重写pop()和push()两个virtual函数即可。  
如果需要，你还可以实现可动态扩展和收缩的资源池。

# 示例
我们准备抓取一份URL列表，但要求总的并发度不超过max_p。我们当然可以用parallel来实现，但使用资源池可以更简单：
~~~cpp
int fetch_with_max(std::vector<std::string>& url_list, size_t max_p)
{
    WFResourcePool pool(max_p);

    for (std::string& url : url_list)
    {
        WFHttpTask *task = WFTaskFactory::create_http_task(url, [&pool](WFHttpTask *task) {
            pool.post(nullptr);
        });
        WFConditional *cond = pool.get(task);  // 无需保存res，可以不传resbuf参数。
        cond->start();
    }

    // wait_here...
}
~~~

# 消息队列

消息队列是一种比资源使用方法类似的组件。它们的区别在于：
* 资源池的总资源数量是固定的，在创建时就已经确定。而消息队列的长度则不受限制。
* 资源池的存取方式是先进后出，刚刚释放的资源会先被复用。而消息队列则是先进先出。
* 资源池使用方式是先获取，后归还。没有获取就直接归还资源，可能导致缓冲区溢出。消息队列没有这样的约束。
* 实现上，资源池使用的是数组，消息队列使用链表。总体来讲，在实现和使用上，消息队列都比资源池简单一些。

# 消息队列接口

在[WFMessageQueue.h](https://github.com/sogou/workflow/blob/master/src/factory/WFMessageQueue.h)里，定义了消息队列模块的接口：
~~~cpp
class WFMessageQueue
{
public:
    WFConditional *get(SubTask *task, void **msgbuf);
    WFConditional *get(SubTask *task);
    void post(void *msg);
    ...

public:
    WFMessageQueue();
    ...
};
~~~
由于了解过资源池的用法，消息队列的使用方式我们也就无需再详细展开。模式和资源池一样，都是在获得消息（或资源）时，任务被拉起。  
消息队列的get和post接口，无需像资源池一样遵循先获取再放回的原则，任何任务都可以随时从队列中存取消息。  
如果有需要，用户同样可以派生WFMessageQueue类，实现先进后出的消息读取模式。  

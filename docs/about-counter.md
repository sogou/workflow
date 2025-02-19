# 关于计数器

计数器是我们框架中一种非常重要的基础任务，计数器本质上是一个不占线程的信号量。  
计数器主要用于工作流的控制，包括匿名计数器和命名计数器两种，可以实现非常复杂的业务逻辑。  

# 计数器的创建

由于计数器也是一种任务，它的创建同样通过WFTaskFactory来完成，包括两种创建方法：
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
每个计数器都包含一个target_value，当计数器的计数到达target_value，callback被调用。  
以上两个接口分别产生匿名计数器和命名计数器，匿名计数器直接通过WFCounterTask的count方法来增加计数：  
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
如果创建计数器时，传入一个counter_name，则产生一个命名计数器，可以通过count_by_name函数来增加计数。  

# 用匿名计数器实现任务并行

在[并行抓取](./tutorial-06-parallel_wget.md)的示例中，我们通过创建一个ParallelWork来实现多个series并行。  
通过ParallelWork和SeriesWork的组合，可以构建任意的串并连图，已经可以满足大多数应用场景需求。  
而计数器的存在，可以让我们构建更复杂的任务依赖关系，比如实现一个全连接的神经网络。  
以下简单的代码，可代替ParallelWork，实现一个并行的http抓取。  
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
以上创建一个目标值为url_count的计数器，每个http任务完成之后，调用一次count。  
注意，匿名计数器的count次数不可以超过目标值，否则counter可能已经callback销毁了，程序行为无定义。  
counter->start()调用可以放在for循环之前。counter只要被创建，就可以调用其count接口，无论counter是否已经启动。  
匿名计数器的count接口调用，也可以写成counter->WFCounterTask::count(); 在非常注重性能的应用下可以这么用。  

# Server与其它异步引擎结合使用

某些情况下，我们的server可能需要调用非本框架的异步客户端等待结果。简单的方法我们可以在process里同步等待，通过条件变量来唤醒。  
这么做的缺点是我们占用了一个处理线程，把其它框架的异步客户端变为同步客户端。但通过counter，我们可以不占线程地等待。  
方法很简单：
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
在这里，我们可以把server任务所在的series理解为一个协程，而目标值为1的counter，可以理解为一个条件变量。  
Counter的缺点是count操作不传递数据。如果业务有数据传达的需求，可以使用[Mailbox任务](https://github.com/sogou/workflow/blob/master/src/factory/WFTaskFactory.h#L268)。  

# 命名计数器

对匿名计数器进行count操作时，直接访问了counter对象指针。这就必然要求在操作时，调用count的次数不超过目标值。  
但想象这样一个应用场景，我们同时启动4个任务，只要其中有任意3个任务完成，工作流就可以继续进行。  
我们可以用一个目标值为3的计数器，每个任务完成之后，count一次，这样只要任务3个任务完成，计数器就被callback。  
但这样的问题是，当第4个任务完成，再调用counter->count()的时候，计数器已经是一个野指针了，程序崩溃。  
这时候我们可以用命名计数器来解决这个问题。通过给计数器命名，并通过名字来计数，例如以下实现：
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
这个示例中，调起4个并发的http任务，其中3个完成了，立刻启动一个redis任务。实际应用中，可能还需要加入数据传递的代码。  
示例中创建命名为"c1"的计数器，在http回调里，使用WFTaskFactory::count_by_name()调用来进行计数。
~~~cpp
class WFTaskFactory
{
    ...
    static int count_by_name(const std::string& counter_name);

    static int count_by_name(const std::string& counter_name, unsigned int n);
    ...
};
~~~
WFTaskFactory::count_by_name方法还可以传入一个整数n，表示这一次操作要增加的计数值，显然：  
count_by_name("c1")等价于count_by_name("c1", 1)。  
如果"c1"计数器不存在（未创建或已经完成），那么对"c1"的操作不产生任何效果，因此不会有匿名计数器野指针的问题。  
函数的返回值表示被唤醒的计数器个数。当n大于1时，count_by_name操作可能让多个计数器达到目标值。  

# 命名计数器详细行为定义

调用WFTaskFactory::count_by_name(name, n)的时候：
* 如果name不存在（未创建或已经完成），无任何行为。
* 如果只有一个名字为name的计数器：
  * 如果该计数器剩余的值小于或等于n，计数完成，callback被调用，该计数器被销毁。结束。
  * 如果计数器剩余值大于n，则计数值加n。结束。
* 如果存在多个同名为name的计数器：
  * 按照创建顺序，取第一个计数器，假设其剩余值为m：
      * 如果m值大于n，则计数加n。结束（剩余值为m-n）。
      * 如果m小于或等于n，计数完成，callback被调用，第一个计数器被销毁。置n=n-m。
          * 如果n为0，结束。
          * 如果n大于0，再取出下一个同名计数器，重复整个的操作。

虽然描述很复杂，但总结起来就一句话，按照创建顺序，依次访问所有名字为name的计数器，直到n为0。  
也就是说，一次count_by_name(name, n)可以唤醒多个计数器。  
用好计数器，可以实现非常复杂的业务逻辑。计数器在我们框架里，往往用于实现异步锁，或者用于任务之间的通道。形态上更像一种控制任务。  

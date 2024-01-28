# 关于定时器

定时器的作用是不占线程的等待一个确定时间，同样通过callback来通知定时器到期。

# 定时器的创建

WFTaskFactory类里包括四个定时相关的接口：
~~~cpp
using timer_callback_t = std::function<void (WFTimerTask *)>;

class WFTaskFactory
{
    ...
public:
    static WFTimerTask *create_timer_task(time_t seconds, long nanoseconds,
                                          timer_callback_t callback);

    static WFTimerTask *create_timer_task(const std::string& timer_name,
                                          time_t seconds, long nanoseconds,
                                          timer_callback_t callback);

    static void cancel_by_name(const std::string& timer_name)
    {
        cancel_by_name(const std::string& timer_name, (size_t)-1);
    }

    static void cancel_by_name(const std::string& timer_name, size_t max);
};
~~~
我们通过seconds和nanoseconds两个参数来指定一个定时器的定时时间。其中，nanoseconds的取值范围在[0,1000000000)。  
在创建定时器任务时，可以传入一个timer_name作为定时器名，用于cancel_by_name接口取消定时。  
定时器也是一种任务，因此使用方式与其它类型任务无异，同样有user_data域可以利用。  

# 中断定时

如果在创建定时器任务时传入一个名称，那么这个定时器就可以在被提前中断。  
中断一个定时任务的方法是通过WFTaskFactory::cancel_by_name这个接口，这个接口默认情况下，会取消这个名称下的所有定时器。  
因此，我们也支持传入一个max参数，让操作最多取消max个定时器。当然，如果没有这个名称下的定时器，cancel操作不会产生任何效果。  
定时器在被创建之后就可取消，并非一定要等它被启动之后。以这个代码为例：
~~~cpp
#include <stdio.h>
#include "workflow/WFTaskFactory.h"

int main()
{
    WFTimerTask *timer = WFTaskFactory::create_timer_task("test", 10000, 0, [](WFTimerTask *){
        printf("timer callback, state = %d, error = %d.\n", task->get_state(), task->get_error());
    });

    WFTaskFactory::cancel_by_name("test");

    timer->start();

    getchar();
    return 0;
}
~~~
程序会在立即打印出'timer callback, state = 1, error = 125."，因为定时器在运行之前就已经被取消了。所以，定时任务启动后立即callback，状态码为WFT_STATE_SYS_ERROR，错误码为ECANCELED。  
使用中需要注意的是，命名定时器比匿名定时器是会多出一些开销的，原因是我们需要维护查找表，会有加锁解锁等操作。如果你的定时器没有提前中断的需要，就不要在创建时传入timer_name了。  

# 程序退出打断定时器

在[关于程序退出](./about-exit.md)里讲到，main函数结束或exit()被调用的时候，所有任务必须里运行到callback，并且没有新的任务被调起。  
这时就可能出现一个问题，定时器的定时周期可以非常长，如果是不可中断的定时器，那么等待定时器到期，程序退出需要很长时间。  
而实现上，程序退出是可以打断定时器，让定时器回到callback的。如果定时器被程序退出打断，get_state()会得到一个WFT_STATE_ABORTED状态。  
当然如果定时器被程序退出打断，则不能再调起新的任务。  
以下这个程序，每间隔一秒抓取一个一个http页面。当所有url抓完毕，程序直接退出，不用等待timer回到callback，退出不会有延迟。  
~~~cpp
bool program_terminate = false;

void timer_callback(WFTimerTask *timer)
{
    mutex.lock();
    if (!program_terminate)
    {
        WFHttpTask *task;
        if (urls_to_fetch > 0)
        {
            task = WFTaskFactory::create_http_task(...);
            series_of(timer)->push_back(task);
        }

        series_of(timer)->push_back(WFTaskFactory::create_timer_task(1, 0, timer_callback));
    }
    mutex.unlock();
}

...
int main()
{
    ....
    /* all urls done */
    mutex.lock();
    program_terminate = true;
    mutex.unlock();
    return 0;
}
~~~
以上程序，timer_callback必须在锁里判断program_terminate条件，否则可能在程序已经结束的情况下又调起新任务。

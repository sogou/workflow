# 关于定时器

定时器的作用是不占线程的等待一个确定时间，同样通过callback来通知定时器到期。

# 定时器的创建

同样是在WFTaskFactory类里的方法：
~~~cpp
using timer_callback_t = std::function<void (WFTimerTask *)>;

class WFTaskFactory
{
    ...
    static WFTimerTask *create_timer_task(unsigned int microseconds,
                                          timer_callback_t callback);
    static WFTimerTask *create_timer_task(time_t seconds, long nanoseconds,
                                          timer_callback_t callback);
};
~~~
目前我们提供两个创建定时器的工厂函数。第一个函数接收一个unsigned int型参，时间单位为微秒。  
如果用户需要更长时间或更高精度的定时，可以使用第二个函数接口。接口接受两个参数，分别为秒和纳秒。实际上，这个接口也具备更高的性能。  
定时器任务里同样有user_data域可以用来传递一些用户数据。启动方法和接入任务流的方法与其它任务没有区别。  

# 定时器的一个高级特征

在[关于程序退出](./about-exit.md)里讲到，main函数结束或exit()被调用的时候，所有任务必须里运行到callback，并且没有新的任务被调起。  
这时就可能出现一个问题，定时器的定时周期可以非常长，并且不能主动打断（打断定时器的功能正在研发）。如果等定时器到期，程序退出需要很长时间。  
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

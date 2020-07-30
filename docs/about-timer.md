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
};
~~~
第一个参数为定时时间，单位为微秒。除了程序退出，定时器不可以提前结束。  
定时器任务里同样有user_data域可以用来传递一些用户数据。启动方法和接入任务流的方法与其它任务没有区别。  

# 定时器的一个高级特征

在[关于程序退出](./about-exit.md)里讲到，main函数结束或exit()被调用的时候，所有任务必须里运行到callback，并且没有新的任务被调起。  
这们就可能出现一个问题，定时器的最长定时时间超过了1小时，并且不能主动打断。如果等定时器到期，程序退出需要很长时间。  
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

        series_of(timer)->push_back(WFTaskFactory::create_timer_task(1000000, timer_callback));
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
由于使用上有一定难度，程序应该尽量避免使用这个特征，而应该等所有定时器都回到callback，再结束程序。  

# 定时时间不够用怎么办

目前定时器最长定时用期约4200秒，如果程序的任务为24小时启动一次，则需要一个24小时的定时。可以简单地添加多个定时器。  
例如：
~~~cpp
void timer_callback(WFTimerTask *timer)
{
    mutex.lock();
    if (program_terminate)
        series_of(timer)->cancel();
    mutex.unlock();
}

void my_callback(WFMyTask *task)
{
    SeriesWork *series = series_of(task);
    WFTimerTask *timer;
    for (int i = 0; i < 24; i++)
    {
        timer = WFTaskFactory::create_timer_task(3600U*1000*1000, timer_callback);
        series->push_back(timer);
    }

    WFMyTask *next_task = MyFactory::create_my_task(..., my_callback);
    series->push_back(next_task);
}
~~~
因为timer_task是一种耗费资源非常小的任务，所以可以创建非常多的timer。上例中创建24个1小时的定时器，每24小时执行一个任务。  
例子中也考虑了程序随时可以退出的问题。在timer的callback里发现程序已经退出，需要cancel余下的任务。  
虽然我们的定时器可以被程序退出中断，而且我们也支持把多个定时器串起来，实现一个很长的定时， 
但这都不是我们推荐的做法。大多数情况下应该避免太长时间的定时，并且应该等所有定时器到期再结束程序。


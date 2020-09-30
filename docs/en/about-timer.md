# About timer

 Timers are used to specify a certain waiting time without occupying a thread. The expiration of a timer is notified also by a callback.

# Creating a timer

You can use the same method in the WFTaskFactory class to create a timer:

~~~cpp
using timer_callback_t = std::function<void (WFTimerTask *)>;

class WFTaskFactory
{
...
    static WFTimerTask *create_timer_task(unsigned int microseconds,
                                          timer_callback_t callback);
};
~~~

The first parameter is the duration in microseconds. Unless the program is terminated, the timer cannot be terminated early.   
There is also a user\_data field in the timer task that can be used to transfer some user data. Its starting method is the same as other tasks, and the procedure for adding it into the workflow is also the same.

# Advanced features of a timer

In [About exit](/docs/en/about-exit.md), you learn that the condition that a main thread can safely end (calls **exit()** or return in the main function) is that all tasks have been run to the callback and no new task is started.   
Then, there may be a problem. As the maximum duration of a timer exceeds one hour and it cannot be interrupted actively, if you wait for the timer to expire, it will take a long time for the program to exit.   
In practice, exiting the program can interrupt the timer and make it return to the callback. If the timer is interrupted by exiting the program, **get\_state()** will return a WFT\_STATE\_ABORTED state.   
Of course, if the timer is interrupted by exiting the program, no new tasks can be started.   
The following program demonstrates crawling one HTTP page at every one second. When all URLs are crawled, the program exits directly without waiting for the timer to return to the callback, and there will be no delay in exiting.

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

In the above program, the timer\_callback must check the program\_terminate condition in the lock, otherwise a new task may be started when the program has terminated. 
As it is difficult in use, the program should avoid using this feature as much as possible, and should wait for all timers to return to the callbacks before its termination.

# What to do if the duration is not enough

Currently, the longest duration of a timer is about 4200 seconds. If the task of the program needs to start once every 24 hours, you need a timer with a duration of 24 hours. In this case, you can simply add multiple timers.   
For example:

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

Because the timer\_task is a task that consumes very little resources, you can create a lot of timers. In the above example, 24 one-hour timers are created to execute a task every 24 hours.   
The above example also consider the scenario that the program may exit at any time. In the callback of the timer, if it is found that the program has been terminated, it is necessary to cancel the remaining tasks.   
Although our timers can be interrupted by exiting the program and we also support to arrange multiple timers in a series to achieve a long duration, but this is not our recommended practice. In most cases, you should avoid using long duration, and you should wait for all timers to expire before exiting the program.

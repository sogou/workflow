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
    static WFTimerTask *create_timer_task(time_t seconds, long nanoseconds,
                                          timer_callback_t callback);
};
~~~

We'v got two factory functions that create timers. The first one accepts one parameter representing the duration in microseconds.  
But if timer with longer or more precise duration is required, you have to use the second function, which accepts two parameters, seconds and nanoseconds, and has better performance.
Unless the program is terminated, the timer cannot be interrupted (**interrupting a timer by user is under development**).   
There is also a user\_data field in the timer task that can be used to transfer some user data. Its starting method is the same as other tasks, and the procedure for adding it into the workflow is also the same.

# Advanced features of a timer

In [About exit](/docs/en/about-exit.md), you learn that the condition that a main thread can safely end (calls **exit()** or return in the main function) is that all tasks have been run to the callback and no new task is started.   
Then, there may be a problem. As the duration of a timer could be long and it cannot be interrupted by users, if you wait for the timer to expire, it will take a long time for the program to exit.   
But in practice, exiting the program can interrupt the timer safely and make it return to the callback. If the timer is interrupted by exiting the program, **get\_state()** will return a WFT\_STATE\_ABORTED state.   
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

In the above program, the timer\_callback must check the program\_terminate condition in the lock, otherwise a new task may be started when the program has terminated. 

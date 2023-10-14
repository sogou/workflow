# About timer

 Timers are used to specify a certain waiting time without occupying a thread. The expiration of a timer is notified also by a callback.

# Creating a timer

Timer interfaces in WFTaskFactory：
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
We specify the timing time of a timer through the seconds and nanoseconds parameters. Among them, the value range of nanoseconds is [0,1000000000). When creating a timer, a timer_name can be specified. And we may interrupt a timer by calling **cancel_by_name** with this name later.  
As a standard workflow task, there is also a user\_data field in the timer task that can be used to transfer some user data. Its starting method is the same as other tasks, and the procedure for adding it into the workflow is also the same.

# Canceling a timer

A named timer can be interrupted throught WFTaskFacotry::cancel_by_name interface, which will cancel all timers under the name by default. So we provide another cancel interface with the second argument **max** for user to cancel at most **max** timers. And of course, if no timer under the name, nothing performed.
You can cancel a timer right after it's created, for example:
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
This program prints 'timer callback, state = 1, error = 125."，immediately because the timer has be canceled before started, and it will run to callback soon after it's started. And the state code would be WFT_STATE_SYS_ERROR and the error code would be ECANCELED.   
By the way, create named timer when and only when you may need to cancel it, because it costs more. In other scenarios just use anonymous timer. 

# Interrupting timer by program exit

In [About exit](/docs/en/about-exit.md), you learn that the condition that a main thread can safely end (calls **exit()** or return in the main function) is that all tasks have been run to the callback and no new task is started.   
Then, there may be a problem, if you wait for the timer to expire, it will take a long time for the program to exit.   
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

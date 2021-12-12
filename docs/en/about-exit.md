# About exit

As most of our calls are non-blocking, we need some mechanisms to prevent the main function from exiting early in the previous examples.   
For example, in the wget example, we wait for the user's Ctrl-C, or in the parallel\_wget example, we wake up the main thread after all crawling tasks are finished.   
In several server examples, the **stop()** operation is blocking, which can ensure the normal end of all server tasks and the safe exit of the main thread.

# Principles on the safe exit

Generally, as long as you writes the program normally and follows the methods in the examples, there is little doubt about exit. However, it is still necessary to define the conditions for normal program exit.

* You can't call **exit()** of the system in any callback functions such as the callback or the process, otherwise the behavior is undefined.
* The condition that a main thread can safely end (call **exit()** or return in the main function) is that all tasks have been run to callbacks and no new tasks is started.
  * All our examples are consistent with this assumption, waking up the main function in the callback. This is safe, and there is no need to worry about the situation where the callback is not finished when the main function returns.
  * ParallelWork is a kind of tasks, which also needs to run to its callback.
  * This rule can be violated under certain circumstances. We will talk about it in the following section.
* All server must stop, otherwise the behavior is undefined. Because all users know how to call the stop operation, generally a server program will not have any exit problems.
  * Server's stop() method will block until all server tasks' series end. But if you start a task directly in process function, you have to take care of the end this task.

# Why do I need to wait for the callback of a running task? Can the program be ended early?

First, explain why you need to wait till the callback of tasks before ending the program.  
In most cases, the tasks generated through the task factory are composite tasks. For example, an http client task may need to resolve the dns, and then initiate the http crawl. And if a 302 redirect is encountered, dns resolving may be needed again. If the task fails, retrying may be involved.  
In other words, any asynchronous tasks may contain multiple asynchronous processes, but it is completely insensitive to users. But between each internal asynchronous process, it does not check whether the program has exited.  
If the user clearly knows that a task is an atomic task, for example, an http task created with an IP address (or a dns cache can definitely be hit), and there is no redirection or retry. Then, this task can be interrupted by the program's exit and come to the callback early, and the state of the task in the callback is WFT_STATE_ABORTED.  
For example, the following program is always safe:
~~~cpp
void callback(WFHttpTask *task)
{
    // most probably print 2，WFT_STATE_ABORTED。
    printf("state = %d\n", task->get_state());
}

int main()
{
    WFHttpTask *task = WFTaskFactory::create_http_task("https://127.0.0.1/", 0, 0, callback);
    task->start();
    // end the main process directly
    return 1;
}
~~~
If the dns cache hits, it is safe. Because there is no need to initiate a dns asynchronous task internally. E.g:
~~~cpp
WFFacilities::WaitGroup wg(1)

void callback_normal(WFHttpTask *task)
{
    wg.done();
}

void callback_abort(WFHttpTask *task)
{
    // most probably print 2，WFT_STATE_ABORTED。
    printf("state = %d\n", task->get_state());
}

int main()
{
    WFHttpTask *task = WFTaskFactory::create_http_task("https://www.sogou.com/", 3, 2, callback_normal);
    task->start();
    // wait for the end of the first task
    wg.wait();
    // Access wwww.sogou.com again. Hit the dns cache definitely.
    WFHttpTask *task = WFTaskFactory::create_http_task("https://www.sogou.com/", 0, 0, callback_abort);
    task->start();
    // end the main process directly
    return 1;
}
~~~
Therefore, for a network task, as long as it can be determined to be an atomic task, it can be interrupted by the end of the program. This principle can be extended to any type of task.  
For example, the timer task is an atomic task, and the following program is also safe:
~~~cpp
void callback(WFTimerTask *task)
{
    // definitely print 2，WFT_STATE_ABORTED。
    printf("state = %d\n", task->get_state());
}
int main()
{
    WFTimerTask *task = WFTaskFactory::create_timer_task(1000000, callback);
    task->start();
    // end the main process directly
    return 1;
}
~~~
In the documentation (About Timer)(https://github.com/sogou/workflow/blob/master/docs/en/about-timer.md), we will describe them in detail.  
In addition, you can also end the program before the callback of single-threaded computing tasks and file IO tasks. Among them, the computing task that is already running, the program will wait for the task to end, and finally callback in the SUCCESS state. If it has not begun running, it will canceled and you will get an ABORTED state in callback.  
As long as the file IO task has been started, it will always wait for the IO to complete. Therefore, it is always safe to exit the program directly.

# About memory leakage of OpenSSL 1.1 in exiting

We found that some OpenSSL 1.1 versions have the problem of incomplete memory release in exiting. The memory leak can be seen by Valgrind memcheck tool.   
This problem only happens when you use SSL, such as crawling HTTPS web pages, and usually you can ignore this leak. If it must be solved, you can use the following method:

~~~cpp
#include <openssl/ssl.h>

int main()
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPENSSL_init_ssl(0, NULL);
#endif
    ...
}
~~~

In other words, before using our library, you should initialize OpenSSL. You can also configure OpenSSL parameters at the same time if necessary.   
Please note that this function is only available in OpenSSL version 1.1 or above, so you need to check the openSSL version before calling it.   
This memory leak is related to the memory release mechanism of OpenSSL 1.1. The solution provided by us can solve this problem (but we still recommend you to ignore it).

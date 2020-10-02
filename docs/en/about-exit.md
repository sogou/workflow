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
  * This rule can be violated under certain circumstances where the procedural behavior is strictly defined. However, if you don't understand the core principles, you should abide by this principle, otherwise the program can't exit normally.
* All server must stop, otherwise the behavior is undefined. Because all users know how to call the stop operation, generally a server program will not have any exit problems.

As long as the above three conditions are met, the program can exit normally without any memory leakage. Despite the strict definition, please note the conditions for the completion of a server stop.

* The call of **stop()** on a server will wait for the callbacks of all server tasks to finish (the callback is empty by default) and no new server tasks are processed.
* However, the framework can't stop you from starting a new task in the process, and not added to the series of the server task. The server **stop()** can't wait for the completion of this new task.
* Similarly, if the user adds a new task (such as logging) to the series of the server task in its callback, the new task is not controlled by the server.
* In both cases, if the main function exits immediately after **server.stop()**, it may violate the second rule above. Because there may still be tasks that have not run to their callback.

In the above situation, you need to ensure that the started task has run to its callback. You can use a counter to record the number of running tasks, and wait for the count value to reach 0 before the main function returns.   
In the following example, in the callback of a server task, a log file writing task is added to the current series (assuming that file writing is very slow and asynchronous IO needs to be started once).

~~~cpp
std::mutex mutex;
std::condition_variable cond;
int log_task_cnt = 0;

void log_callback(WFFileIOTask *log_task)
{
    mutex.lock();
    if (--log_task_cnt == 0)
        cond.notify_one();
    mutex.unlock();
}

void reply_callback(WFHttpTask *server_task)
{
    WFFileIOTask *log_task = WFTaskFactory::create_pwrite_task(..., log_callback);

    mutex.lock();
    log_task_cnt++;
    mutex.unlock();
    *series_of(server_task) << log_task;
}

int main(void)
{
    WFHttpServer server;

    server.start();
    pause();
    ...

    server.stop();

    std::unique_lock<std::mutex> lock(mutex);
    while (log_task_cnt != 0)
        cond.wait(lock);
    lock.unlock();
    return 0;
}
~~~

Although the above method is feasible, it does increase the complexity and the error probability of the program, which should be avoided as much as possible. For example, you can write log directly in reply callback.

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

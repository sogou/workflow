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
  * Server's stop() method will block until all server tasks' series end. But if you start a task directly in process function, you have to take care of the end this task.

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

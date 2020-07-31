# 关于程序退出

由于我们的大多数调用都是非阻塞的，所以在之前的示例里我们都需要用一些机制来防止main函数提前退出。  
例如wget示例中等待用户的Ctrl-C，或者像parallel_wget在所有抓取结束之后唤醒主线程。  
而在几个server的示例中，stop()操作是阻塞的，可以确保所有server task的正常结束，主线程可安全退出。

# 程序安全退出的原则

一般情况下，用户只要正常写程序，模仿示例中的方法，不太会有什么关于退出的疑惑。但这里还是需要把程序正常退出的条件定义好。  
* 用户不可以在callback或process等任何回调函数里调用系统的exit()函数，否则行为无定义。
* 主线程可以安全结束（main函数调用exit()或return）的条件是所有任务已经运行到callback，并且没有新的任务被调起。
  * 我们所有的示例都符合这个假设，在callback里唤醒main函数。这是安全的，不用担心main返回的时候，callback还没结束的情况。
  * ParallelWork是一种task，也需要运行到callback。
  * 这一条规则某下情况下可以违反，并且程序行为有严格定义。但不了解核心原理的使用者请遵守这条规则，否则程序无法正常退出。
* 所有server必须stop完成，否则行为无定义。因为stop操作用户都会调，所以一般的server程序不会有什么退出方面的问题。

只要符合以上三个条件，程序都是可以正常退出，没有任何内存泄露。虽然定义非常严密，但是这里有一个注意事项，就是关于server stop完成的条件。
* server的stop()调用，会等所有的server任务callback结束（默认这个callback为空），而且不会有新的server任务被处理。
* 但是，如果用户在process里，启动一个新的任务，不在server task所在的series里，这件事框架并不能阻止，并且server stop无法等这个任务完成。
* 同样，如果用户在server task的callback里，向task所在的series里加入一个新任务（比如打log），那么这个新任务也不受server控制。
* 以上两种情况，如果server.stop()之后main函数立刻退出，那么就有可能违反上面的第二条规则。因为还有任务没有运行到callback。

针对上面这个情况，用户需要保证启动的任务已经到callback。方法可以用计数器记录有多少个运行中的任务，在main返回前等待这个数归0。  
例如以下示例，server任务的callback里，在当前series加入一个打log的文件写任务（假设写文件非常慢，需要启动一次异步IO）：
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
以上这个方法虽然可行，但也确实增加了程序的复杂度和出错误几率，应该尽量避免。例如可直接在reply callback里写log。

# 关于OpenSSL 1.1版本在退出时的内存泄露

我们发现某些openssl1.1版本，存在退出时内存释放不完全的问题，通过valgrind内存检查工具可以看出内存泄露。  
这个问题只有在用户使用了SSL，例如抓取了https网页时才会发生，而且一般情况下用户可以忽略这个泄露。
如果一定要解决，方法如下：
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
也就是说在使用我们的库之前，先初始化openssl。如果你有需要也可以同时配置openssl的参数。  
注意这个函数只在openssl1.1以上版本才有提供，所以调用之前需要先判断openssl版本。  
这个内存泄露与openssl1.1的内存释放原理有关。我们提供的这个方案可以解决这个问题（但我们还是建议用户忽略）。

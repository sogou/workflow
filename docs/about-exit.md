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
  * 这一条规则某下情况下可以违反，我们将在下一节解释。
* 所有server必须stop完成，否则行为无定义。因为stop操作用户都会调，所以一般server程序不会有什么退出方面的问题。
  * server的stop会等待所有server任务所在series结束。但如果用户在process直接start一个新任务，则需要考虑任务结束的问题。

# 为什么需要等待运行中的任务callback？能不能提前结束程序？

首先解释一下需要等待任务callback再结束程序的原因。在大多数情况下，我们通过任务工厂产生的任务，都是一个复合任务。  
http抓取任务为例，一个http任务可能需要先解析dns，再发起http抓取。如遇到302重定向，可能需要再次dns。任务失败可能还会重试。  
也就是说，我们一个异步任务可能包含多个异步过程，但对用户完全无感。而内部每个异步过程之间，并不会检查程序是否已经退出。  
如果用户明确知道一个任务是原子任务，例如以IP地址（或肯定能dns cache命中）创建http任务，并且无重定向或重试。  
那么，这个任务可以被程序退出打断并提前来到callback，callback里任务的状态是WFT_STATE_ABORTED。  
例如以下程序是绝对安全的：
~~~cpp
void callback(WFHttpTask *task)
{
    // 这里打印的结果大概率是2，WFT_STATE_ABORTED。
    printf("state = %d\n", task->get_state());
}

int main()
{
    WFHttpTask *task = WFTaskFactory::create_http_task("https://127.0.0.1/", 0, 0, callback);
    task->start();
    // 这里直接结束程序
    return 1;
}
~~~
如果dns cache命中，也是安全的。因为内部无需再发起一个dns异步任务了。例如：
~~~cpp
WFFacilities::WaitGroup wg(1);

void callback_normal(WFHttpTask *task)
{
    wg.done();
}

void callback_abort(WFHttpTask *task)
{
    // 这里打印的结果大概率是2，WFT_STATE_ABORTED。
    printf("state = %d\n", task->get_state());
}

int main()
{
    WFHttpTask *task = WFTaskFactory::create_http_task("https://www.sogou.com/", 3, 2, callback_normal);
    task->start();
    // 等待第一个访问www.sogou.com的任务结束。
    wg.wait();
    // 第二次访问www.sogou.com, dns信息已经被cache。
    WFHttpTask *task = WFTaskFactory::create_http_task("https://www.sogou.com/", 0, 0, callback_abort);
    task->start();
    // 这里直接结束程序
    return 1;
}
~~~
所以，对于网络任务而言，只要能确定是一个原子任务，都可以被程序结束打断。这个原则可以扩展到任何类型的任务。  
例如，定时器任务是一个就原子任务，以下程序也是绝对安全的：
~~~cpp
void callback(WFTimerTask *task)
{
    // 这里打印的结果肯定是2，WFT_STATE_ABORTED。
    printf("state = %d\n", task->get_state());
}
int main()
{
    WFTimerTask *task = WFTaskFactory::create_timer_task(1000000, callback);
    task->start();
    // 这里直接结束程序
    return 1;
}
~~~
在[关于定时器](https://github.com/sogou/workflow/blob/master/docs/about-timer.md)的文档里，我们将会详细展开描述。  
此外，单线程的计算任务，文件IO任务，也可以在callback之前直接结束程序。  
其中，已经在执行计算的计算任务，程序会等待计算结束，最终以SUCCESS状态callback。还未被调起的，则以ABORTED状态退出。  
文件IO任务，只要已经start，肯定会等待IO完成。因此直接退出程序完全安全。

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

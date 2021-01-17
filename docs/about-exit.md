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
* 所有server必须stop完成，否则行为无定义。因为stop操作用户都会调，所以一般server程序不会有什么退出方面的问题。
  * server的stop会等待所有server task所在series结束。但如果用户在process直接start一个新任务，则需要自己考虑任务结束的问题。

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

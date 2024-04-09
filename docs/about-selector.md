# 关于Selector任务

我们业务中经常有一些需求，从几个异步分支中选择第一个成功完成的结果进行处理，丢弃其它结果。  
Selector任务就是为了上述这种多选一场景而设计的。  

# Selector解决的问题
常见的多选一场景例如：  
* 向多个下游发送网络请求，只要任意一个下游返回正确结果，工作流程就可以继续。
* 执行一组复杂的操作，操作执行完成或整体超时，流程都会继续。
* 并行计算中，任何一个线程计算出预期的结果即完成，例如MD5碰撞计算。
* 网络应用中的‘backup request’，也可以用selector配合timer来实现。

在selector任务被引入之前，这些场景很难被很好解决，涉及到任务生命周期以及丢弃结果的资源回收等问题。    

# 创建Selector任务
Selector也是一种任务，所以一般由WFTaskFactory里的工厂函数产生：
~~~cpp
using selector_callback_t = std::function<void (WFSelectorTask *)>;

class WFTaskFactory
{
public:
    static WFSelectorTask *create_selector_task(size_t candidates,
                                                selector_callback_t callback);
};
~~~
其中，candidates参数代表从多少个候选路径中选择。Selector任务创建后，必须有candidates次被提交才会被销毁。  
因此，用户可以放心的（也是必须的）向selector提交candidates次，无需要担心selector的生命周期问题。  

# Selector类的接口
WFSelectorTask类包括两个主要接口。其中，对提交者来讲，只需要关注submit函数。对于等待者，只需使用到get_message。  
~~~cpp
class WFSelectorTask : public WFGenericTask
{
public:
    virtual int submit(void *msg);

    void *get_message() const;
};
~~~
当第一个非空指针的msg被提交，submit函数返回1表示接受。随后的submit调用都返回0代表消息被拒绝。  
Selector运行后接收到一个有效消息就进入callback了，但在收到所有submit之前，不会被销毁。  
注意空指针永远不会被接受，所以submit一个NULL将返回0。一般来讲，submit(NULL)用于表示这个分支失败了。  
如果所有候选都提交了NULL，selector运行到callback时，state=WFT_STATE_SYS_ERROR, error=ENOMSG。  
作为等待者，在selector的callback里调用另外一个接口get_message()就可以得到被成功接受的消息了。  

# 示例
我们同时抓取两个http网页，并设置一个超时。当任意一个先抓取成功或超时，打印出抓取成功的URL或出错信息。  
示例中使用wait group来保证两个抓取任务已经结束才退出程序。而timer可以被程序退出打断，无需等待。  
~~~cpp
#include <stdlib.h>
#include <stdio.h>
#include "workflow/WFTaskFactory.h"
#include "workflow/WFFacilities.h"

WFSelectorTask *selector;
WFFacilities::WaitGroup wait_group(2);

void http_callback(WFHttpTask *t)
{
    if (t->get_state() == WFT_STATE_SUCCESS)
        selector->submit(t->user_data);
    else
        selector->submit(NULL);

    wait_group.done();
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        fprintf(stderr, "USAGE: %s <http URL1> <http URL2> <timeout>\n", argv[0]);
        exit(1); 
    }

    selector = WFTaskFactory::create_selector_task(3, [](WFSelectorTask *selector) {
        void *msg = selector->get_message();
        if (msg)
            printf("%s\n", (char *)msg);
        else
            printf("failed\n");
    });

    auto *t = WFTaskFactory::create_http_task(argv[1], 0, 0, http_callback);
    t->user_data = argv[1];
    t->start();

    t = WFTaskFactory::create_http_task(argv[2], 0, 0, http_callback);
    t->user_data = argv[2];
    t->start();

    auto *timer = WFTaskFactory::create_timer_task(atoi(argv[3]), 0, [](WFTimerTask *timer){
        if (timer->get_state() == WFT_STATE_SUCCESS)
            selector->submit((void *)"timeout");
        else
            selector->submit(NULL);
    });
    timer->start();

    selector->start();

    wait_group.wait();
    return 0;
}
~~~




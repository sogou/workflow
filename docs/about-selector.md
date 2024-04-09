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
当第一个候选者通过submit提交了一个非空指针的msg，这个消息会被接受。如果任务已经启动，selector的callback被调用。  
和其它任何类型的任务一样，callback结束之后，任务所在的series就继续执行了，无需等待其它候选被提交。  
当一个候选消息被接受，submit函数返回1。之后的submit调用都返回0表示拒绝。一般这种情况下用户需要释放msg对应资源。  
注意空指针永远不会被接受，所以submit一个NULL永远返回0。一般来讲，submit(NULL)用于表示这个分支失败了。  
如果所有候选都提交了NULL，selector运行到callback时，state=WFT_STATE_SYS_ERROR, error=ENOMSG。  
作为等待者，在selector的callback里调用另外一个接口get_message()就可以得到被成功接受的消息了。

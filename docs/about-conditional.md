# 条件任务与观察者模式

有的时候，我们需要让任务在某个条件下才被执行。条件任务（WFConditional）就是用于解决这种问题。  
条件任务是一种任务包装器，可以包装任何的任务并取代原任务。通过对条件任务发送信号来触发被包装任务的执行。  

# 条件任务的创建
在[WFTaskFactory.h](/src/factory/WFTaskFactory.h)里，可以看到条件任务的创建接口。
~~~cpp
class WFTaskFactory
{
public:
    static WFConditional *create_conditional(SubTask *task);
    static WFConditional *create_conditional(SubTask *task, void **msgbuf);
};
~~~
可以看到，我们通过工厂的create_conditional接口创建条件任务。  
其中，task为被包装的任务。msgbuf是用于接收消息的缓冲区，如果无需关注消息的具体内容，msgbuf可以缺省。  
WFConditional的主要接口：
~~~cpp
class WFConditional : public WFGenericTask
{
public:
    virtual void signal(void *msg);
    ...
};
~~~
WFConditional是一种任务，所以，它满足普通workflow任务的一切属性。特别的接口只有signal，用于发送信号。  

# 示例

以下示例，通过timer和conditional，实现一个延迟1秒执行的计算任务。
~~~cpp
int main()
{
    WFGoTask *task = WFTaskFactory::create_go_task("test", [](){ printf("Done\n"); });
    WFConditional *cond = WFTaskFactory::create_conditional(task);
    WFTimerTask *timer = WFTaskFactory::create_timer_task(1, 0, [cond](void *){
        cond->signal(NULL);
    });
    timer->start();
    cond->start();
    getchar();
}
~~~
这个示例里，在定时器的回调里向cond发送信号，让被包装的go task可以被执行。  
注意，无论cond->signal()与cond->start()哪一个先被调用，程序都完全正确。  

# 观察者模式

我们看到，如果直接对cond发送信息，需要发送者直接持有cond的指针，这在一些情况下并不是很方便。  
于是，我们引入了观察者模式，也就是命名的条件任务。通过向某个名称发送信号，同时唤醒所有在这个名称下的条件任务。  
命名条件任务的创建与唤醒：
~~~cpp
class WFTaskFactory
{
public:
    static WFConditional *create_conditional(const std::string& cond_name, SubTask *task);
    static WFConditional *create_conditional(const std::string& cond_name, SubTask *task, void **msgbuf);
    static void signal_by_name(const std::string& cond_name, void *msg);
};
~~~
我们看到，与普通条件任务唯一区别是，命名条件任务创建时，需要传入一个cond_name。  
而signal_by_name()接口，将msg发送到所有在这个名称上等待的条件任务，将它们全部唤醒。这就相当于实现了观察者模式。  
# 示例

还是上面的延迟计算示例，我们增加到两个计算任务并用观察者模式来实现。用”slot1”作为条件任务名。
~~~cpp
int main()
{
    WFGoTask *task1 = WFTaskFactory::create_go_task("test”, [](){ printf(“test1 done\n"); });
    WFGoTask *task2 = WFTaskFactory::create_go_task("test”, [](){ printf(“test2 done\n"); });
    WFConditional *cond1 = WFTaskFactory::create_conditional(“slot1”, task1);
    WFConditional *cond2 = WFTaskFactory::create_conditional(“slot1”, task2);
    WFTimerTask *timer = WFTaskFactory::create_timer_task(1, 0, [](void *){
        WFTaskFactory::signal_by_name(“slot1”, NULL);
    });
    timer->start();
    cond1->start();
    cond2->start();
    getchar();
}
~~~
我们看到，在这个示例里，timer在回调中通过signal_by_name方法，同时唤醒了slot1下两个计算任务。  

# 使用条件任务注意事项

Workflow里的任何任务，如果创建之后不想运行，都可以通过dismiss接口直接释放。  
对于条件任务，如果要被dismiss（或者在某个被cancel的series里），必须保证这个条件任务没有被signal过。
以下代码的行为无定义：
~~~cpp
int main()
{
    WFEmptyTask *task = WFTaskFactory::create_empty_task();
    WFConditional *cond = WFTaskFactory::create_conditional(“slot1”, task);
    WFTimerTask *timer = WFTaskFactory::create_timer_task(0, 0, [](void *) {
        WFTaskFactory::signal_by_name(“slot1”);
    });
    timer->start();
    cond->dismiss();  // 取消任务
    getchar();
}
~~~
显然，如果timer的callback里已经执行或正在执行了signal_by_name，cond被signal，再dismiss()是一种错误行为。  
这种情况一般也只会出现在命名条件任务里。所以，dismiss一个命名条件任务，需要特别的小心。  

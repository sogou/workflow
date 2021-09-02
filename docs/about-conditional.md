# 条件任务与资源池

在我们用workflow与异步程序时经常会遇到这样一些场景：
* 任务运行时需要先从某个池子里获得一个资源。任务运行结束，则会把资源放回池子，让下一个需要资源的任务运行。
* 网络通信时需要对某一个或一些通信目标做总的并发度限制，但又不希望占用线程等待。
* 我们有许多随机到达的任务，处在不同的series里。但这些任务必须**串行**的运行。

所有这些需求，都可以用workflow的资源池组件来优雅解决。这个模块对workflow项目的发展至关重要。  
目前，我们们的异步dns模块，就是通过这个方法来实现对dns server的并发度控制的。

# 资源池的接口
在[WFResourcePool.h](https://github.com/sogou/workflow/blob/master/src/factory/WFResourcePool.h)里，定义了资源池模块的接口：
~~~cpp
// WFResourcePool.h

class WFResourcePool
{
public:
    WFConditional *get(SubTask *task, void **resbuf);
    void post(void *res);
    ...

public:
    WFResourcePool(void *const *res, size_t n);
    WFResourcePool(size_t n);
    ...
};
~~~

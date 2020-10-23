# 关于go task

我们提供了另一种更简单的使用计算任务的方法，模仿go语言实现的go task。  
使用go task来实计算任务无需定义输入与输出，所有数据通过函数参数传递。

# 创建go task
~~~cpp
class WFTaskFactory
{
    ...
public:
    template<class FUNC, class... ARGS>
    static WFGoTask *create_go_task(const std::string& queue_name,
                                    FUNC&& func, ARGS&&... args);
};
~~~

# 示例
我们想异步的运行一个加法函数：void add(int a, int b, int& res);  
并且我们还想在函数运行结束的时候打印出结果。于是可以这样实现：
~~~cpp
#include <stdio.h>
#include <utility>
#include "workflow/WFTaskFactory.h"
#include "workflow/WFFacilities.h"

void add(int a, int b, int& res)
{
    res = a + b;
}

int main(void)
{
    WFFacilities::WaitGroup wait_group(1);
    int a = 1;
    int b = 1;
    int res;

    WFGoTask *task = WFTaskFactory::create_go_task("test", add, a, b, std::ref(res));
    task->set_callback([&](WFGoTask *task) {
        printf("%d + %d = %d\n", a, b, res);
        wait_group.done();
    });
 
    task->start();
    wait_group.wait();
    return 0;
}
~~~
以上的示例异步运行一个加法，打印结果并退出程序。go task的使用与其它的任务没有多少区别，也有user_data域可以使用。  
唯一一点不同，是go task创建时不传callback，但和其它任务一样可以set_callback。  
如果go task函数的某个参数是引用，需要使用std::ref，否则会变成值传递，这是c++11的特征。

# 把workflow当成线程池

用户可以只使用go task，这样可以将workflow退化成一个线程池，而且线程数量默认等于机器cpu数。  
但是这个线程池比一般的线程池又有更多的功能，比如每个任务有queue name，任务之间还可以组成各种串并联或更复杂的依赖关系。


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

# 带执行时间限制的go task
通过create_timedgo_task接口（这里无法重载create_go_task接口），可以创建带时间限制的go task：
~~~cpp
class WFTaskFactory
{
    /* Create 'Go' task with running time limit in seconds plus nanoseconds.
     * If time exceeded, state WFT_STATE_ABORTED will be got in callback. */
    template<class FUNC, class... ARGS>
    static WFGoTask *create_timedgo_task(time_t seconds, long nanoseconds,
                                         const std::string& queue_name,
                                         FUNC&& func, ARGS&&... args);
};
~~~
相比创建普通的go task，create_timedgo_task函数需要多传两个参数，seconds和nanoseconds。  
如果func的运行时间到达seconds+nanosconds时限，task直接callback，且state为WFT_STATE_ABORTED。  
注意，框架无法中断用户执行中的任务。func依然会继续执行到结束，但不会再次callback。另外，nanoseconds取值区间在\[0,10亿）。  
另外，当我们给go task加上了运行时间限制，callback的时机可能会先于func函数的结束，任务所在series可能也会先于func结束。  
如果我们在func里访问series，可能就是一个错误了。例如：
~~~cpp
void f(SeriesWork *series)
{
    series->set_context(...);   // 错误。当f是一个带超时的go task，此时series可能已经失效了。
}

int http_callback(WFHttpTask *task)
{
    SeriesWork *series = series_of(task);
    WFGoTask *go = WFTaskFactory::create_timedgo_task(1, 0, "test", f, series);  // 1秒超时的go task
    series_of(task)->push_back(go);
}
~~~
这也是为什么，我们不推荐在计算任务的执行函数里，对任务所在的series进行操作。对series的操作，应该在callback里进行，例如：
~~~cpp
int main()
{
    WFGoTask *task = WFTaskFactory::create_timedgo_task(1, 0, "test", f);
    task->set_callback([](WFGoTask *task) {
        SeriesWork *series = series_of(task):
        void *context = series->get_context();
        if (task->get_state() == WFT_STATE_SUCCESS) // 成功执行完
        {
             ...
        }
        else // state == WFT_STATE_ABORTED.         // 超过运行时间限制
        {
             ...
        }
    });
}
~~~
但是，在计算函数里使用task，是安全的。所以，可以使用task->user_data，在计算函数和callback之间传递数据。例如：
~~~cpp
int main()
{
    WFGoTask *task = WFTaskFactory::create_timedgo_task(1, 0, "test", [&task]() {
        task->user_data = (void *)123;
    });
    task->set_callback([](WFGoTask *task) {
        SeriesWork *series = series_of(task):
        void *context = series->get_context();
        if (task->get_state() == WFT_STATE_SUCCESS) // 成功执行完
        {
		    int result = (int)task->user_data;
        }
        else // state == WFT_STATE_ABORTED.         // 超过运行时间限制
        {
		    ...
        }
    });
    task->start();
    ...
}
~~~~
# 重置go task的执行函数
在某些时候，我们想在go task的执行函数里访问task，如上面的例子，将计算结果写入task的user_data域。  
上例中，我们使用了引用捕获。但明显引用捕获会有一些问题。比如task本身的生命周期。我们更希望在执行函数里直接捕获go task指针。  
直接进行值捕获明显是错误的，例如：
~~~cpp
WFGoTask *task = WFTaskFactory::create_timedgo_task(1, 0, "test", [task]() {
        task->user_data = (void *)123;
    });
~~~
这段代码并不能在lambda函数里得到task指针，因为捕获执行时，task还没有赋值。但我们可以通过以下的代码，实现这个需求：
~~~cpp
WFGoTask *task = WFTaskFactory::create_timedgo_task(1, 0, "test", [](){});
WFTaskFactory::reset_go_task(task, [task]() {
        task->user_data = (void *)123;
    });
~~~
WFTaskFactory::reset_get_task()函数，用于重置go task的执行函数。  
因为task已经创建完毕，这时候在lambda函数里捕获task，就是一个正确的行为了。


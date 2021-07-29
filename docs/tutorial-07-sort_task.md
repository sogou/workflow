# 使用内置算法工厂：sort_task
# 示例代码

[tutorial-07-sort_task.cc](/tutorial/tutorial-07-sort_task.cc)

# 关于sort_task

程序从命令行读入数字n，将随机的n个正整数先升序排列，再把结果再降序排列。 
程序可加入第二个参数"p"，则可以进行并行排序。例如：  
$ ./sort_task 100000000 p  
上面的命令将先升序排列1亿个整数，再降序排列。两次排序都采用并行。  

# 关于计算任务

计算任务（或称线程任务），是我们非常重要的一个功能。在使用我们任务流的时候，并不建议在callback里直接进行非常复杂的计算。  
所有需要消耗大量CPU时间的计算，都可以封装成计算任务交给系统去调度。计算任务和通信任务在使用方法上并没有什么区别。  
系统的算法工厂提供了一些常用的计算任务，比如排序，归并等。用户也可以很方便定义自己的计算任务。

# 创建升序排序任务
~~~cpp
int main(int argc, char *argv[])
{
    ...
    WFSortTask<int> *task;
    if (use_parallel_sort)
        task = WFAlgoTaskFactory::create_psort_task("sort", array, end, callback);
    else
        task = WFAlgoTaskFactory::create_sort_task("sort", array, end, callback);
    ...
    task->start();
    ...
}
~~~
和WFHttpTask或WFRedisTask不同，排序任务多了一个模板参数代表要排序的数组数据类型。  
create_sort_task和create_psort_task分别产生一个普通排序任务和一个并行排序任务。  
这两个调用的参数和返回值并没有区别。  
唯一需要特别说明的是第一个参数"sort"，这个是计算队列名，用于影响内部的任务调度。本篇文档后面会介绍队列名的用法。  
计算任务的启动方法与使用方法和网络通信任务并没有什么区别。  

# 处理结果

和通信任务一样，我们在callback里处理结果。这个示例里，升序排序之后会再发起一次降序排序。
~~~cpp
using namespace algorithm;

void callback(void SortTask<int> *task)
{
    SortInput<T> *input = task->get_input();
    int *first = input->first;
    int *last = input->last;

    // print result
    ...
    
    if (task->user_data == NULL)
    {
        auto cmp = [](int a1, int a2){ return a2 < a1; };
        WFSortTask<int> *reverse;

        if (use_parallel_sort)
            reverse = WFAlgoTaskFactory::create_psort_task("sort", first, last, cmp, callback);
        else
            reverse = WFAlgoTaskFactory::create_sort_task("sort", first, last, cmp, callback);
            
        reverse->user_data = (void *)1; /* as a flag */
        series_of(task)->push_back(reverse);
    }
    else
    {
        // all done. Signal main thread to exit.
        ... 
    }
}
~~~
计算任务的get_input()接口得到输入数据，get_output()得到输出数据。对于排序任务，输入和输出是相同类型，内容也完全相同。  
在[WFAlgoTaskFactory.h](../src/factory/WFAlgoTaskFactory.h)里，可以看到排序任务输入输出的定义：
~~~cpp
namespace algorithm
{

template <typename T>
struct SortInput
{
    T *first;
    T *last;
};

template <typename T>
using SortOutput = SortInput<T>;

}

template <typename T>
using WFSortTask = WFThreadTask<algorithm::SortInput<T>,
                                algorithm::SortOutput<T>>;

template <typename T>
using sort_callback_t = std::function<void (WFSortTask<T> *)>;

~~~
显然，input或output里的first, last分别为排序数组的首尾指针。  
接下来我们会创建一个降序排序的任务，这时候，我们就需要传进去一个比较函数了。  
~~~cpp
        auto cmp = [](int a1, int a2)->bool{ return a2 < a1; };
        reverse = WFAlgoTaskFactory::create_sort_task("sort", first, last, cmp, callback);
~~~
可以说我们的用法和std::sort()区别不是很大。但我们的first和last是指针，而不是用iterator。  
同样，用create_psort_task()可以创建一个并行排序任务。而对series的使用，和通信任务没有区别。  

# 关于计算线程数的配置

如果你不做任何配置，计算调度器将使用当前机器CPU个数的线程数。你也可以通过以下的方式，修改这个值：
~~~cpp
#include "workflow/WFGlobal.h"

int main()
{
    struct WFGlobalSettings settings = GLOBAL_SETTINGS_DEFAULT;
    settings.compute_threads = 16;
    WORKFLOW_library_init(&settings);
    ...
}
~~~
通过上面的配置，我们将创建16个线程用于计算。

# 关于并行排序算法

内置的并行排序算法，使用分块+二路归并。空间复杂度为O(1)。  
算法使用全局配置的计算线程进行计算，但最多使用128个线程。因为不使用额外空间，加速比会小于线程数量，平均CPU占用也比较小。  
具体实现可参考[WFAlgoTaskFactory.inl](../src/factory/WFAlgoTaskFactory.inl)

# 关于计算队列名

我们的计算任务并没有优化级的概念，唯一可以影响调度顺序的是计算任务的队列名，本示例中队列名为字符串"sort"。  
队列名的指定非常简单，需要说明以下几点：  
  * 队列名是一个静态字符串，不可以无限产生新的队列名。例如不可以根据请求id来产生队列名，因为内部会为每个队列分配一小块资源。  
  * 当计算线程没有被100%占满，所有任务都是实时调起，队列名没有任何影响。
  * 如果一个服务流程里有多个计算步骤，穿插在多个网络通信之间，可以简单的给每种计算步骤起一个名字，这个会比整体用一个名字要好。
    * 如果所有计算任务用同一个名字，那么所有任务的被调度的顺序与提交顺序一致，在某些场景下会影响平均响应时间。
    * 每种计算任务有一个独立名字，那么相当于每种任务之间是公平调度的，而同一种任务内部是顺序调度的，实践效果更好。
  * 总之，除非机器的计算负载已经非常繁重，否则没有必要特别关心队列名，只要每种任务起一个名字就可以了。

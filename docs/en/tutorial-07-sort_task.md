# Using the built-in algorithm factory: sort\_task

# Sample code

[tutorial-07-sort\_task.cc](/tutorial/tutorial-07-sort_task.cc)

# About sort\_task

The program reads a number n from the command line,  sorts the random n positive integers in ascending order, and then sorts the results in descending order. You can add the second parameter "p” to the program, and then it can be sorted in parallel. For example:  
 ./sort\_task 100000000 p   
The above command will sort 100 million integers in ascending order and then in descending order. The two sortings are done in parallel respectively.

# About computing tasks

Computing tasks (or thread tasks) is a very important function in the framework. When you use the task flow, it is not recommended to directly perform very complicated computation in the callback.   
All the computations that consume a lot of CPU time can be encapsulated into computing tasks and handed over to the system for scheduling. There is no difference in the usage between computing tasks and networking tasks.   
The algorithm factory of the system provides some common computing tasks, such as sorting, merging and so on. You can also easily define your own computing tasks.

# Creating sorting tasks in ascending order 

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

Unlike WFHttpTask or WFRedisTask, the sorting task has one more template parameter to represent the type of array data to be sorted.   
**create\_sort\_task** and **create\_psort\_task** produce a common sorting task and a parallel sorting task respectively.   
Their ****parameters and return values are the same.****   
The only thing that needs special explanation is the first parameter "sort", which is the name of the computation queue. It is used to instruct the internal task scheduling. The latter part in this article explains the usage of the queue name.   
There is no difference in the starting methods and usage between computing tasks and networking tasks.

# Handling results

Like a networking task, the results are handled in the callback. In this example, the ascending sorting is followed by one descending sorting.

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

You can use **get\_input ()** interface of a computing task to get the input data, and use **get\_output ()** to get the output data. For sorting tasks, the input and output are of the same type, and the content are exactly the same.   
[WFAlgoTaskFactory.h](/src/factory/WFAlgoTaskFactory.h) contains the definitions of the input and output of sorting tasks.

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

Obviously, the first and last in the input or output mean the head pointer and the tail pointer of the array to be sorted.   
Next, we will create a descending sorting task. In this case, we need to pass in a comparison function.

~~~cpp
        auto cmp = [](int a1, int a2)->bool{ return a2 < a1; };
        reverse = WFAlgoTaskFactory::create_sort_task("sort", first, last, cmp, callback);
~~~

Our usage differs slightly from **std::sort()**. Our first and last are pointers, not iterators.   
Similarly, you can use **create\_psort\_task()** to create a parallel sorting task. And the use of series in the sorting task is no different from that in the networking task.

# About the configuration of the computing threads

If you don't make any configuration, the calculation scheduler will set the number of threads as the number of the CPU cores in the machine. You can change the value with the following method:

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

With the above configuration, the system will create 16 threads for computations.

# About the parallel sorting algorithm

The built-in parallel sorting algorithm use block+two-way merge. Its space complexity is O(1).   
The algorithm uses globally configured computing threads for computation, but at most 128 threads can be used. Because no extra space is used, the speedup ratio will be smaller than the number of threads, and the average CPU usage will be smaller.   
For the detailed implementation, please see [WFAlgoTaskFactory.inl](/src/factory/WFAlgoTaskFactory.inl).

# About the name of a calculation task queue

The computing task does not have priority levels. The only thing that can affect the scheduling order is the queue name of a computing task. In this example, the queue name is a string "sort".   
To name a queue is very simple. Please note the following items:

* The queue name is a static string, and new queue names cannot be generated infinitely. For example, you cannot generate the queue name according to the request id, because each queue is allocated a small block of resources internally.
* If the computing threads are not 100% occupied, all tasks are started in real time, and the queue names have no effect.
* If there are multiple computing steps in a service flow and they are interspersed among multiple network communications, you can simply give each calculation step a name, which is better than using one name as a whole.
  * If all computing tasks use the same name, the scheduling order of all tasks is consistent with the  order of submission, which will affect the average response time in some scenarios.
  * If each kind of computing task has an independent name, it means that they are scheduled fairly. And the same kind of tasks are scheduled sequentially, the practical effect is better.
* In a word, unless the computing load of the machine is already very heavy, you do not need to pay special attention to the queue name and you can just give each kind of task a name.

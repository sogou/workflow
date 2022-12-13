# About go task

We provide a simpler way to use computing task, which is inspired by the golang, and we name it 'go task'.  
When using go task, no input nor output type has to be defined. All data are passed through function's arguments.

# Creating a go task
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

# Example
We want to run an 'add' function asychronously: void add(int a, int b, int& res);  
Still, we want the result printed after the 'add' function is finished. We may create a go task:
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
The above example runs an add function asynchronously, prints the result and exits normally. The creating and running of go task have little difference from other kinds of tasks, and the user_data field is also available.  
Note that when creating a go task, we donot pass a callback function. But you may set_callback later like other kinds of tasks.  
If an argument of the go task's function is a reference, you should use `std::ref` when passing it to the task, otherwise it will be passed as a value. 

# Go task with running time limit
You may create a go task with running time limit by calling WFTaskFactory::create_timedgo_task():
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
Compared with creating a normal go task, the ``create_timedgo_task`` function needs to pass two more parameters, seconds and nanoseconds. If the running time of ``func`` reaches the seconds+nanosconds time limit, the task callback directly, and the state is WFT_STATE_ABORTED.  
Note that the framework cannot interrupt the user's ongoing task. ``func`` will still continue to execute to the end, but will not callback again. In addition, the value range of nanoseconds is [0,1 billion).


# Use the whole library as a thread pool

You may use go task only. In this way the workflow library becomes a thread pool，and the default thread number is equal to the cpu number of the host.  
But this thread pool has some special features. Every thread task is associated with a queue name that will indicate scheduling, and you may set up the dependency of all tasks too.


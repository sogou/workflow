# About Module Task

Our **series** has tasks as elements. But in many cases, users need module-level encapsulation, such as several tasks to complete a specific function. With the original method, you have to let the callback of the last task connect to the next task, or fill in the response of the server task. Therefore, we introduced WFModuleTask, which is convenient for users to encapsulate modules and reduce the coupling of tasks between different functional modules.

# Create a Module Task

We define a **module** as a kind of task, WFModuleTask. Inside the module includes a sub_series for running tasks within the module. Any task doesn't need to care if it runs inside a module. Because the sub_series inside the module is no different from the normal series.  
In [WFTaskFactory.h](/src/factory/WFTaskFactory.h), the creation interface of module task:
~~~cpp
using module_callback_t = std::function<void (const WFModuleTask *)>;

class WFTaskFactory
{
    static WFModuleTask *create_module_task(SubTask *first, module_callback_t callback);
};
~~~
The first create_module_task() is the first task of the module. Similar to creating a series.  
The module task’s callback request a **const** pointer argument in order to prevent user pushing more tasks to module in callback.

# WFModuleTask Interfaces

Because we define modules as this kind of task, we can use modules like any other task. But modules do not have **state** and **error** fields.  
In [WFTask.h](/src/factory/WFTask.h), we define the class of WFModuleTask:
~~~cpp
class ModuleTask : public ParallelTask, protected SeriesWork
{
public:
    void start() { .. }
    void dismiss() { ... }

public:
    SeriesWork *sub_series() { return this; }
    const SeriesWork *sub_series() const { return this; }

public:
    void *user_data;
};
~~~
The **sub_series** interface returns the series of tasks running in the module. A module is essentially a sub-flow.  
sub_series is also an ordinary series, and users can call its set_context(), get_context(), push_back() and other functions.  
But we don't recommend setting a callback for sub_series, use module task’s callback instead.    

# Example

In the processing logic of an http server, we design all processing logic as a module.
~~~cpp
struct ModuleCtx {
    std::string body;
};

void http_callback(WFHttpTask *http_task)
{
    SeriesWork *series = series_of(http_task);    // This series is module’s sub_series
    struct ModuleCtx *ctx = (struct ModuleCtx *)series->get_context();
    const void *body;
    size_t size;
    If (http_task->get_resp()->get_parsed_body(&body, &size))
    {
        ctx->body.assign(body, size);
    }

    ParallelWork *pwork = Workflow::create_parallel_work(…)；// Do some other things
    series->push_back(pwork);
}

void process(WFHttpTask *server_task)
{
    WFHttpTask *http_task = WFTaskFactory::create_http_task(…, http_callback);
    WFModuleTask *module = WFTaskFactory::create_module_task(http_task, [server_task](const WFModuleTask *mod) {
        struct ModuleCxt *ctx = (ModuleCtx *)mod->sub_series()->get_context();
        server_task->get_resp()->append_output_body(ctx->body);
        delete ctx;
    });
    module->sub_series()->set_context(new ModuleCtx);
    series_of(server_task)->push_back(module);
}
~~~
Through this method, the tasks in the module only need to operate the series context, and finally the **resp** is filled in by the callback of the module. Task coupling is greatly reduced.

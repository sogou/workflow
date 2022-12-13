# 关于模块任务

我们的任务流是以task为元素。但很多情况下，用户需要模块级的封装，比如几个task完成一个特定的功能。  
用原有的方法，就不得不让最后一个task的callback来衔接下一个任务，或者填写server任务的resp。这样不太合理。  
因此，我们引入了WFModuleTask，方便用户封装模块，降低不同功能模块之间task的耦合。

# 模块任务的创建

我们把模块定义成一种特殊的任务，WFModuleTask。模块的内部包括一个sub_series用于运行模块内的任务。  
对任务来讲，它无需关心自己是否运行在模块内。因为模块内的sub_series和普通series没有任何区别。  
在[WFTaskFactory.h](/src/factory/WFTaskFactory.h)里，包括了包括了模块任务的创建接口：
~~~cpp
using module_callback_t = std::function<void (const WFModuleTask *)>;

class WFTaskFactory
{
    static WFModuleTask *create_module_task(SubTask *first, module_callback_t callback);
};
~~~
create_module_task()的第一个参数first代表模块首任务，这与创建series类似。  
module callback参数要求是const指针。这主要是防止用户在callback里，继续向module中添加任务。  

# WFModuleTask的主要接口

因为我们把模块也定义成这一种任务，所以，可以像使用其它任务一样使用模块。但模块没有state和error域。  
在[WFTask.h](/src/factory/WFTask.h)里，定义了WFModuleTask类。
~~~cpp
class ModuleTask : public ParallelTask, protected SeriesWork // 不必关注这个派生关系
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
module特有的sub_series接口返回module内任务运行的series。module本质上是一个子任务流。  
sub_series也是一个普通的series，用户可以调用它的set_context()，get_context()，push_back()等函数。  
但我们不太建议给sub_series设置callback，因为没有什么必要，使用module的callback就可以了。  
注意，在module的callback参数表，是const WFModuleTask \*，也就只能得到一个const的sub_series。  
因此，在模块任务的callback里，只能调用sub_series的get_context()得到series上下文。  

# 示例

在一个http server的处理逻辑中，我们把所有处理逻辑设计成一个模块。
~~~cpp
struct ModuleCtx
{
    std::string body;
};

void http_callback(WFHttpTask *http_task)
{
    SeriesWork *series = series_of(http_task);    // 这个series就是module的sub_series。
    struct ModuleCtx *ctx = (struct ModuleCtx *)series->get_context();
    const void *body;
    size_t size;

    if (http_task->get_resp()->get_parsed_body(&body, &size))
    {
        ctx->body.assign(body, size);
    }

    ParallelWork *pwork = Workflow::create_parallel_work(…)；// 做一些别的操作
    series->push_back(pwork);
}

void process(WFHttpTask *server_task)
{
    WFHttpTask *http_task = WFTaskFactory::create_http_task(…, http_callback);
    WFModuleTask *module = WFTaskFactory::create_module_task(http_task, [server_task](const WFModuleTask *mod) {
        struct ModuleCxt *ctx = (struct ModuleCtx *)mod->sub_series()->get_context();
        server_task->get_resp()->append_output_body(ctx->body);
        delete ctx;
    });
    module->sub_series()->set_context(new ModuleCtx);
    series_of(server_task)->push_back(module);
}
~~~
通过这个方法，module里的任务只需操作series context，最终由module的callback汇总填写resp。任务耦合性大幅降低。

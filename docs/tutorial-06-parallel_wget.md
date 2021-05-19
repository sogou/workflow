# 一个简单的并行抓取：parallel_wget
# 示例代码

[tutorial-06-parallel_wget.cc](/tutorial/tutorial-06-parallel_wget.cc)

# 关于parallel_wget

这是我们第一个并行任务的示例。  
程序从命令行读入多个http URL（以空格分割），并行抓取这些URL，并按照输入顺序将抓取结果打印到标准输出。

# 创建并行任务

之前的示例里，我们已经接触过了SeriesWork类。
  * SeriesWork由任务构成，代表一系列任务的串行执行。所有任务结束，则这个series结束。  
  * 与SeriesWork对应的ParallelWork类，parallel由series构成，代表若干个series的并行执行。所有series结束，则这个parallel结束。  
  * ParallelWork是一种任务。  

根据上述的定义，我们就可以动态或静态的生成任意复杂的工作流了。  
Workflow类里，有两个接口用于产生并行任务：
~~~cpp
class Workflow
{
    ...
public:
    static ParallelWork *
    create_parallel_work(parallel_callback_t callback);

    static ParallelWork *
    create_parallel_work(SeriesWork *const all_series[], size_t n,
                         parallel_callback_t callback);

    ...
};
~~~
第一个接口创建一个空的并行任务，第二个接口用一个series数组创建并行任务。  
无论用哪个接口产生的并行任务，在启动之前都可以用ParallelWork的add_series()接口添加series。  
在示例代码里，我们创建一个空的并行任务，并逐个添加series。
~~~cpp
int main(int argc, char *argv[])
{
    ParallelWork *pwork = Workflow::create_parallel_work(callback);
    SeriesWork *series;
    WFHttpTask *task;
    HttpRequest *req;
    tutorial_series_context *ctx;
    int i;

    for (i = 1; i < argc; i++)
    {
        std::string url(argv[i]);
        ...
        task = WFTaskFactory::create_http_task(url, REDIRECT_MAX, RETRY_MAX,
            [](WFHttpTask *task)
        {
            // store resp to ctx.
        });

        req = task->get_req();
        // add some headers.
        ...

        ctx = new tutorial_series_context;
        ctx->url = std::move(url);
        series = Workflow::create_series_work(task, nullptr);
        series->set_context(ctx);
        pwork->add_series(series);
    }
    ...
}
~~~
从代码中看到，我们先创建http任务，但http任务并不能直接加入到并行任务里，需要先用它创建一个series。  
每个series都带有context，用于保存url和抓取结果。相关的方法我们在之前的示例里都介绍过。

# 保存和使用抓取结果

http任务的callback是一个简单的lambda函数，把抓取结果保存在自己的series context里，以便并行任务获取。
~~~cpp
    task = WFTaskFactory::create_http_task(url, REDIRECT_MAX, RETRY_MAX,
        [](WFHttpTask *task)
    {
        tutorial_series_context *ctx =
            (tutorial_series_context *)series_of(task)->get_context();
        ctx->state = task->get_state();
        ctx->error = task->get_error();
        ctx->resp = std::move(*task->get_resp());
    });
~~~
这个做法是必须的，因为http任务在callback之后就会被回收，我们只能把resp通过std::move()操作移走。  
而在并行任务的callback里，我们可以很方便的获得结果：
~~~cpp
void callback(const ParallelWork *pwork)
{
    tutorial_series_context *ctx;
    const void *body;
    size_t size;
    size_t i;

    for (i = 0; i < pwork->size(); i++)
    {
        ctx = (tutorial_series_context *)pwork->series_at(i)->get_context();
        printf("%s\n", ctx->url.c_str());
        if (ctx->state == WFT_STATE_SUCCESS)
        {
            ctx->resp.get_parsed_body(&body, &size);
            printf("%zu%s\n", size, ctx->resp.is_chunked() ? " chunked" : "");
            fwrite(body, 1, size, stdout);
            printf("\n");
        }
        else
            printf("ERROR! state = %d, error = %d\n", ctx->state, ctx->error);

        delete ctx;
    }
}
~~~
在这里，我们看到ParallelWork的两个新接口，size()和series_at(i)，分别获得它的并行series个数，和第i个并行series。  
通过series->get_context()取到对应series的上下文，打印结果。打印顺序必然和我们放入顺序一致。  
在这个示例中，并行任务执行完就没有其它工作了。  
我们上面说过，ParallelWork是一种任务，所以同样我们可以用series_of()获得它所在的series并添加新任务。  
但是，如果新任务还要使用到抓取结果，我们需要再次用std::move()把数据移到并行任务所在series的上下文里。  

# 并行任务启动

并行任务是一种任务，所以并行任务的启动并没有什么特别，可以直接调用start()，也可以用它建立或启动一个series。  
在这个示例里，我们启动一个series，在这个series的callback里唤醒主进程，正常退出程序。  
我们也可以在并行任务的callback里唤醒主进程，程序行为上区别不大。但在series callback里唤醒更加规范一点。


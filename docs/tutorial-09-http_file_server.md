# 异步IO的http server：http_file_server
# 示例代码

[tutorial-09-http_file_server.cc](../tutorial/tutorial-09-http_file_server.cc)

# 关于http_file_server

http_file_server是一个web服务器，用户指定启动端口，根路径（默认为程序当路程），就可以启动一个web server。  
用户还可以指定一个PEM格式的certificate file和key file，启动一个https web server。  
程序主要展示了磁盘IO任务的用法。在Linux系统下，我们利用了Linux底层的aio接口，文件读取完全异步。

# 启动server

启动server这块，和之前的echo server或http proxy没有什么大区别。在这里只是多了一种SSL server的启动方式：
~~~cpp
class WFServerBase
{
    ...
    int start(unsigned short port, const char *cert_file, const char *key_file);
    ...
};
~~~
也就是说，start操作可以指定一个PEM格式的cert文件和key文件，启动一个SSL server。  
此外，我们在定义server时，用std::bind()给process绑定了一个root参数，代表服务的根路径。
~~~cpp
void process(WFHttpTask *server_task, const char *root)
{
    ...
}

int main(int argc, char *argv[])
{
    ...
    const char *root = (argc >= 3 ? argv[2] : ".");
    auto&& proc = std::bind(process, std::placeholders::_1, root);
    WFHttpServer server(proc);

    // start server
    ...
}
~~~

# 处理请求

与http_proxy类似，我们不占用任何线程读取文件，而是产生一个异步的读文件任务，在读取完成之后回复请求。  
再次说明一下，我们需要把完整回复数据读取到内存，才开始回复消息。所以不适合用来传输太大的文件。
~~~cpp
void process(WFHttpTask *server_task, const char *root)
{
    // generate abs path.
    ...

    int fd = open(abs_path.c_str(), O_RDONLY);
    if (fd >= 0)
    {
        size_t size = lseek(fd, 0, SEEK_END);
        void *buf = malloc(size);        /* As an example, assert(buf != NULL); */
        WFFileIOTask *pread_task;

        pread_task = WFTaskFactory::create_pread_task(fd, buf, size, 0,
                                                      pread_callback);
        /* To implement a more complicated server, please use series' context
         * instead of tasks' user_data to pass/store internal data. */
        pread_task->user_data = resp;    /* pass resp pointer to pread task. */
        server_task->user_data = buf;    /* to free() in callback() */
        server_task->set_callback([](WFHttpTask *t){ free(t->user_data); });
        series_of(server_task)->push_back(pread_task);
    }
    else
    {
        resp->set_status_code("404");
        resp->append_output_body("<html>404 Not Found.</html>");
    }
}
~~~
与http_proxy产生一个新的http client任务不同，这里我们通过factory产生了一个pread任务。  
在[WFTaskFactory.h](../src/factory/WFTaskFactory.h)里，我们可以看到相关的接口。
~~~cpp
struct FileIOArgs
{
    int fd;
    void *buf;
    size_t count;
    off_t offset;
};

...
using WFFileIOTask = WFFileTask<struct FileIOArgs>;
using fio_callback_t = std::function<void (WFFileIOTask *)>;
...

class WFTaskFactory
{
public:
    ...
    static WFFileIOTask *create_pread_task(int fd, void *buf, size_t count, off_t offset,
                                           fio_callback_t callback);

    static WFFileIOTask *create_pwrite_task(int fd, void *buf, size_t count, off_t offset,
                                            fio_callback_t callback);
    ...
};
~~~
无论是pread还是pwrite，返回的都是WFFileIOTask。这与不区分sort或psort，不区分client或server task是一个道理。  
除这两个接口还有preadv和pwritev，返回WFFileVIOTask，以及fsync，fdsync，返回WFFileSyncTask。可以在头文件里查看。  
目前我们这套接口需要用户自行打开关闭fd，我们正在研发一套文件管理，将来用户只需要传入文件名，对跨平台更友好。  
示例用了task的user_data域保存服务的全局数据。但对于大服务，我们推荐使用series context。可以参考前面的[proxy示例](../tutorial/tutorial-05-http_proxy.cc)。

# 处理读文件结果

~~~cpp
using namespace protocol;

void pread_callback(WFFileIOTask *task)
{
    FileIOArgs *args = task->get_args();
    long ret = task->get_retval();
    HttpResponse *resp = (HttpResponse *)task->user_data;

    close(args->fd);
    if (ret < 0)
    {
        resp->set_status_code("503");
        resp->append_output_body("<html>503 Internal Server Error.</html>");
    }
    else /* Use '_nocopy' carefully. */
        resp->append_output_body_nocopy(args->buf, ret);
}
~~~
文件任务的get_args()得到输入参数，这里是FileIOArgs结构。  
get_retval()是操作的返回值。当ret < 0, 任务错误。否则ret为读取到数据的大小。  
在文件任务里，ret < 0与task->get_state() != WFT_STATE_SUCCESS完全等价。  
buf域的内存我们是自己管理的，可以通过append_output_body_nocopy()传给resp。  
在回复完成后，我们会free()这块内存，这个语句在process里：  
server_task->set_callback([](WFHttpTask *t){ free(t->user_data); });

# 关于文件异步IO的实现

Linux操作系统支持一套效率很高，CPU占用非常少的异步IO系统调用。在Linux系统下使用我们的框架将默认使用这套接口。  
我们曾经实现过一套posix aio接口用于支持其它UNIX系统，并使用线程的sigevent通知方式，但由于其效率太低，已经不再使用了。  
目前，对于非Linux系统，异步IO一律是用多线程实现，在IO任务到达时，实时创建线程执行IO任务，callback回到handler线程池。  
多线程IO也是macOS下的唯一选择，因为macOS没有良好的sigevent支持，posix aio行不通。  
多线程IO不支持preadv和pwritev两种任务，创建并运行这两种任务，会在callback里得到一个ENOSYS错误。  
某些UNIX系统不支持fdatasync调用，这种情况下，fdsync任务将等价于fsync任务。


# 关于错误处理

任何软件系统里，错误处理都是一个重要而复杂的问题。在我们框架内部，错误处理可以说是无处不在并且极其繁琐的。  
而在我们暴露给用户的接口里，我们尽可能地让事情变简单，但用户还是不可避免地需要了解一些错误信息。

### 禁用C++异常

我们框架内不使用C++异常，用户编译自己代码的时候，最好也加上-fno-exceptions标志，以减少代码大小。  
参考业界通用做法，我们会忽略new操作失败的可能，并且内部也避免用new去分配大块内存。而C语言风格的内存分配则是有查错的。  

### 关于工厂函数

从之前的实例中我们看到，所有的task，series都是从WFTaskFactory或Workflow这两个工厂类产生的。  
这些工厂类，以及我们以后可能遇到的更多的工厂类接口，都是确保成功的。也就是说，一定不会返回NULL。用户无需对返回值做检查。  
为了达到这个目的，当URL不合法时，工厂也能正常产生task。并且在任务的callback里再得到错误。

### 任务的状态和错误码

在之前的示例里，我们经常在callback里看到这样的代码：
~~~cpp
void callback(WFXxxTask *task)
{
    int state = task->get_state();
    int error = task->get_error();
    ...
}
~~~
其中，state代表任务的结束状态，在[WFTask.h](../src/factory/WFTask.h)文件中，可以看到所有可能的状态值：
~~~cpp
enum
{
    WFT_STATE_UNDEFINED = -1,
    WFT_STATE_SUCCESS = CS_STATE_SUCCESS,
    WFT_STATE_TOREPLY = CS_STATE_TOREPLY,        /* for server task only */
    WFT_STATE_NOREPLY = CS_STATE_TOREPLY + 1,    /* for server task only */
    WFT_STATE_SYS_ERROR = CS_STATE_ERROR,
    WFT_STATE_SSL_ERROR = 65,
    WFT_STATE_DNS_ERROR = 66,                    /* for client task only */
    WFT_STATE_TASK_ERROR = 67,
    WFT_STATE_ABORTED = CS_STATE_STOPPED         /* main process terminated */
};
~~~
##### 需要关注的几个状态：
  * SUCCESS：任务成功。client接收到完整的回复，或server把回复完全写进入发送缓冲（但不能确保对方一定能收到）。
  * SYS_ERROR: 系统错误。这种情况，task->get_error()得到的是系统错误码errno。
    * 当get_error()得到ETIMEDOUT，可以调用task->get_timeout_reason()进一步得到超时原因。
  * DNS_ERROR: DNS解析错误。get_error()得到的是getaddrinfo()调用的返回码。关于DNS，有一篇文档专门说明[about-dns.md](./about-dns.md)。
    * server任务永远不会有DNS_ERROR。
  * SSL_ERROR: SSL错误。get_error()得到的是SSL_get_error()的返回值。
    * 目前SSL错误信息没有做得很全，得不到ERR_get_error()的值。所以，基本上get_error()返回值也就三个可能：
      * SSL_ERROR_ZERO_RETURN, SSL_ERROR_X509_LOOKUP, SSL_ERROR_SSL。
    * 更加详细的SSL错误信息，我们在后续版本会考虑加入。
  * TASK_ERROR: 任务错误。常见的例如URL不合法，登录失败等。get_error()的返回值可以在[WFTaskError.h](../src/factory/WFTaskError.h)中查看。

##### 用户一般无需关注的几个状态：
  * UNDEFINED: 刚创建完，还没有运行的client任务，状态是UNDEFINED。
  * TOREPLY: server任务回复之前，没有被调用过task->noreply()，都是TOREPLY状态。
  * NOREPLY: server任务被调用了task->noreply()之后，一直是NOREPLY状态。callback里也是这个状态。连接会被关闭。

### 其它错误处理需求
除了任务本身的错误处理，各种具体协议的消息接口上，也会有判断错误的需要。一般这些接口都通过返回false来表示错误，并且通过errno传递错误原因。  
此外，一些更复杂的用法，可能需要接触到更复杂一点的错误信息。我们在具体的文档里再做介绍。

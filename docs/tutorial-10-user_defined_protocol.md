# 简单的用户自定义协议client/server
# 示例代码

[message.h](/tutorial/tutorial-10-user_defined_protocol/message.h)  
[message.cc](/tutorial/tutorial-10-user_defined_protocol/message.cc)  
[server.cc](/tutorial/tutorial-10-user_defined_protocol/server.cc)  
[client.cc](/tutorial/tutorial-10-user_defined_protocol/client.cc)  

# 关于user_defined_protocol

本示例设计一个简单的通信协议，并在协议上构建server和client。server将client发送的消息转换成大写并返回。

# 协议的格式

协议消息包含一个4字节的head和一个message body。head是一个网络序的整数，指明body的长度。  
请求和响应消息的格式一致。

# 协议的实现

用户自定义协议，需要提供协议的序列化和反序列化方法，这两个方法都是ProtocolMessage类的虚函数。  
另外，为了使用方便，我们强烈建议用户实现消息的移动构造和移动赋值（用于std::move()）。
在[ProtocolMessage.h](../src/protocol/ProtocolMessage.h)里，序列化反序列化接口如下：
~~~cpp
namespace protocol
{

class ProtocolMessage : public CommMessageOut, public CommMessageIn
{
private:
    virtual int encode(struct iovec vectors[], int max);

    /* You have to implement one of the 'append' functions, and the first one
     * with arguement 'size_t *size' is recommmended. */
    virtual int append(const void *buf, size_t *size);
    virtual int append(const void *buf, size_t size);

    ...
};

}
~~~
### 序列化函数encode
  * encode函数在消息被发送之前调用，每条消息只调用一次。
  * encode函数里，用户需要将消息序列化到一个vector数组，数组元素个数不超过max。目前max的值为2048。
  * 结构体struct iovec定义在请参考系统调用readv和writev。
  * encode函数正确情况下的返回值在0到max之间，表示消息使用了多少个vector。
    * 如果是UDP协议，请注意总长度不超过64k，并且使用不超过1024个vector（Linux一次writev只能1024个vector）。
      * UDP协议只能用于client，无法实现UDP server。
  * encode返回-1表示错误。返回-1时，需要置errno。如果返回值>max，将得到一个EOVERFLOW错误。错误都在callback里得到。
  * 为了性能考虑vector里的iov_base指针指向的内容不会被复制。所以一般指向消息类的成员。

### 反序列化函数append
  * append函数在每次收到一个数据块时被调用。因此，每条消息可能会调用多次。
  * buf和size分别是收到的数据块内容和长度。用户需要把数据内容复制走。
    * 如果实现了append(const void \*buf, size_t \*size)接口，可以通过修改\*size来告诉框架本次消费了多少长度。收到的size - 消费的size = 剩余的size，剩余的那部分buf会由下一次append被调起时再次收到。此功能更方便协议解析，当然用户也可以全部复制走自行管理，则无需修改\*size。
  * append函数返回0表示消息还不完整，传输继续。返回1表示消息结束。-1表示错误，需要置errno。
  * 总之append的作用就是用于告诉框架消息是否已经传输结束。不要在append里做复杂的非必要的协议解析。

### errno的设置
  * encode或append返回-1或其它负数都会被理解为失败，需要通过errno来传递错误原因。用户会在callback里得到这个错误。
  * 如果是系统调用或libc等库函数失败（比如malloc）,libc肯定会设置好errno，用户无需再设置。
  * 一些消息不合法的错误是比较常见的，比如可以用EBADMSG，EMSGSIZE分别表示消息内容错误，和消息太大。
  * 用户可以选择超过系统定义errno范围的值来表示一些自定义错误。一般大于256的值是可以用的。
  * 请不要使用负数errno。因为框架内部用了负数来代表SSL错误。

在我们的示例里，消息的序列化反序列化都非常的简单。  
头文件[message.h](../tutorial/tutorial-10-user_defined_protocol/message.h)里，声明了request和response类：
~~~cpp
namespace protocol
{

class TutorialMessage : public ProtocolMessage
{
private:
    virtual int encode(struct iovec vectors[], int max);
    virtual int append(const void *buf, size_t size);
    ...
};

using TutorialRequest = TutorialMessage;
using TutorialResponse = TutorialMessage;

}
~~~
request和response类，都是同一种类型的消息。直接using就可以。  
注意request和response必须可以无参数的被构造，也就是说需要有无参数的构造函数，或完全没有构造函数。  
此外，通讯过程中，如果发生重试，response对象会被销毁并重新构造。因此，它最好是一个RAII类。否则处理起来会比较复杂。  
[message.cc](../tutorial/tutorial-10-user_defined_protocol/message.cc)里包含了encode和append的实现：
~~~cpp
namespace protocol
{

int TutorialMessage::encode(struct iovec vectors[], int max/*max==8192*/)
{
    uint32_t n = htonl(this->body_size);

    memcpy(this->head, &n, 4);
    vectors[0].iov_base = this->head;
    vectors[0].iov_len = 4;
    vectors[1].iov_base = this->body;
    vectors[1].iov_len = this->body_size;

    return 2;    /* return the number of vectors used, no more then max. */
}

int TutorialMessage::append(const void *buf, size_t size)
{
    if (this->head_received < 4)
    {
        size_t head_left;
        void *p;

        p = &this->head[this->head_received];
        head_left = 4 - this->head_received;
        if (size < 4 - this->head_received)
        {
            memcpy(p, buf, size);
            this->head_received += size;
            return 0;
        }

        memcpy(p, buf, head_left);
        size -= head_left;
        buf = (const char *)buf + head_left;

        p = this->head;
        this->body_size = ntohl(*(uint32_t *)p);
        if (this->body_size > this->size_limit)
        {
            errno = EMSGSIZE;
            return -1;
        }

        this->body = (char *)malloc(this->body_size);
        if (!this->body)
            return -1;

        this->body_received = 0;
    }

    size_t body_left = this->body_size - this->body_received;

    if (size > body_left)
    {
        errno = EBADMSG;
        return -1;
    }

    memcpy(this->body, buf, size);
    if (size < body_left)
        return 0;

    return 1;
}

}
~~~
encode的实现非常简单，固定使用了两个vector，分别指向head和body。需要注意iov_base指针必须指向消息类的成员。  
append需要保证4字节的head接收完整，再读取message body。而且我们并不能保证第一次append一定包含完整的head，所以过程略为繁琐。  
append实现了size_limit功能，超过size_limit的会返回EMSGSIZE错误。用户如果不需要限制消息大小，可以忽略size_limit这个域。  
由于我们要求通信协议是一来一回的，所谓的“TCP黏包”问题不需要考虑，直接当错误消息处理。  
现在，有了消息的定义和实现，我们就可以建立server和client了。　

# server和client的定义

有了request和response类，我们就可以建立基于这个协议的server和client。前面的示例里我们介绍过Http协议相关的类型定义：
~~~cpp
using WFHttpTask = WFNetworkTask<protocol::HttpRequest,
                                 protocol::HttpResponse>;
using http_callback_t = std::function<void (WFHttpTask *)>;

using WFHttpServer = WFServer<protocol::HttpRequest,
                              protocol::HttpResponse>;
using http_process_t = std::function<void (WFHttpTask *)>;
~~~
同样的，对这个Tutorial协议，数据类型的定义并没有什么区别：
~~~cpp
using WFTutorialTask = WFNetworkTask<protocol::TutorialRequest,
                                     protocol::TutorialResponse>;
using tutorial_callback_t = std::function<void (WFTutorialTask *)>;

using WFTutorialServer = WFServer<protocol::TutorialRequest,
                                  protocol::TutorialResponse>;
using tutorial_process_t = std::function<void (WFTutorialTask *)>;
~~~

# server端

server与普通的http server没有什么区别。我们优先IPv6启动，这不影响IPv4的client请求。另外限制请求最多不超过4KB。  
代码请自行参考[server.cc](../tutorial/tutorial-10-user_defined_protocol/server.cc)  

# client端

client端的逻辑是从标准IO接收用户输入，构造出请求发往server并得到结果。这里我们使用了WFRepeaterTask来实现这个重复过程，直到用户的输入为空。
此外，为了安全我们限制server回复包不超4KB。  
client端唯一需要了解的就是怎么产生一个自定义协议的client任务，在[WFTaskFactory.h](../src/factory/WFTaskFactory.h)有四个接口可以选择：
~~~cpp
template<class REQ, class RESP>
class WFNetworkTaskFactory
{
private:
	using T = WFNetworkTask<REQ, RESP>;

public:
	static T *create_client_task(TransportType type,
								 const std::string& host,
								 unsigned short port,
								 int retry_max,
								 std::function<void (T *)> callback);

	static T *create_client_task(TransportType type,
								 const std::string& url,
								 int retry_max,
								 std::function<void (T *)> callback);

	static T *create_client_task(TransportType type,
								 const ParsedURI& uri,
								 int retry_max,
								 std::function<void (T *)> callback);

	static T *create_client_task(TransportType type,
								 const struct sockaddr *addr,
								 socklen_t addrlen,
								 int retry_max,
								 std::function<void (T *)> callback);

    ...
};
~~~
其中，TransportType指定传输层协议，目前可选的值包括TT_TCP，TT_UDP，TT_SCTP和TT_TCP_SSL。  
四个接口的区别不大，在我们这个示例里暂时不需要URL，我们用域名和端口来创建任务。  
如果用户需要使用Unix Domain Protocol访问server，则需要用最后一个接口，直接传入sockaddr。  
实际的调用代码如下。我们派生了WFTaskFactory类，但这个派生并非必须的。
~~~cpp
using namespace protocol;

class MyFactory : public WFTaskFactory
{
public:
    static WFTutorialTask *create_tutorial_task(const std::string& host,
                                                unsigned short port,
                                                int retry_max,
                                                tutorial_callback_t callback)
    {
        using NTF = WFNetworkTaskFactory<TutorialRequest, TutorialResponse>;
        WFTutorialTask *task = NTF::create_client_task(TT_TCP, host, port,
                                                       retry_max,
                                                       std::move(callback));
        task->set_keep_alive(30 * 1000);
        return task;
    }
};
~~~
可以看到我们用了WFNetworkTaskFactory<TutorialRequest, TutorialResponse>类来创建client任务。  
接下来通过任务的set_keep_alive()接口，让连接在通信完成之后保持30秒，否则，将默认采用短连接。  
client的其它代码涉及的知识点在之前的示例里都包含了。请参考[client.cc](../tutorial/tutorial-10-user_defined_protocol/client.cc)

# 内置协议的请求是怎么产生的

现在系统中内置了http, redis，mysql，kafka，dns等协议。我们可以通过相同的方法产生一个http或redis任务吗？比如：  
~~~cpp
WFHttpTask *task = WFNetworkTaskFactory<protocol::HttpRequest, protocol::HttpResponse>::create_client_task(...);
~~~
需要说明的是，这样产生的http任务，会损失很多的功能，比如，无法根据header来识别是否用持久连接，无法识别重定向等。  
同样，如果这样产生一个MySQL任务，可能根本就无法运行起来。因为缺乏登录认证过程。  
一个kafka请求可能需要和多台broker有复杂的交互过程，这样创建的请求显然也无法完成这一过程。  
可见每一种内置协议消息的产生过程都远远比这个示例复杂。同样，如果用户需要实现一个更多功能的通信协议，还有许多代码要写。

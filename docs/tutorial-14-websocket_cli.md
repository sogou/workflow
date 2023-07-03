# Workflow第一个双工通信客户端：websocket_cli

# 示例代码

[tutorial-14-websocket_cli.cc](/tutorial/tutorial-14-websocket_cli.cc)

# 关于websocket_cli

这是一个可以收发**WebSocket**协议的client，也是第一个在**Workflow**上实现的双工通信协议。

运行方式：**./websocket_cli \<URL\>**

URL格式：**ws://host:port** 或 **wss://host:port**

- port缺省值为80；
- 如果是ssl，URL格式为：wss://host:port
- ssl的port缺省值为443；

# 创建并启动WebSocket任务

首先需要创建一个``WebSocketClient``对象，并且通过``init()``函数进行初始化。具体接口参考：[WFWebSocketClient.h](/src/client/WFWebSocketClient.h)

```cpp
WebSocketClient client(process);
client.init(URL);
...
```

构造client时需要传入``process()``函数，这是我们收消息的处理函数，类型为：``std::function<void (WFWebSocketTask *)>``，与**Workflow**其他``process()``的语义类似。

``init()``中需要传入**URL**，如果**UR**L非法，则``init()``会返回-1表示**URL**解析失败。

然后就可以通过client创建任务了，用法与**Workflow**其他协议类似：

```cpp
WFWebSocketTask *task = client.create_websocket_task(callback);
WebSocketFrame *msg = text_task->get_msg();
msg->set_text_data("This is Workflow websocket client.");
task->start();
```

我们通过``create_websocket_task()``的接口创建一个往外发数据的任务，并传入回调函数**callback**。task可以通过``get_msg()``接口拿到要发送的消息体，我们往消息体里填入要发送的数据。因为**WebSocket**协议支持**文本**和**二进制**的数据，所以我们使用``set_text_data()``接口，表示传入的是文本消息。最后把任务**start**起来。task相关的具体接口可以查看：[WFChannel.h](/src/factory/WFChannel.h)

```cpp
using WFWebSocketTask = WFChannelTask<protocol::WebSocketFrame>;
using websocket_callback_t = std::function<void (WFWebSocketTask *)>;
using websocket_process_t = std::function<void (WFWebSocketTask *)>;
```

# 发消息

**WebSocket**的消息体为``WebSocketFrame``，可以在[WebSocketMessage.h](/src/protocol/WebSocketMessage.h)查看到具体接口：

```cpp
class WebSocketFrame : public ProtocolMessage
{
public:
    bool set_opcode(int opcode);
    int get_opcode() const;

    void set_masking_key(uint32_t masking_key);

    bool set_text_data(const char *data);
    bool set_text_data(const char *data, size_t size, bool fin);

    bool set_binary_data(const char *data, size_t size);
    bool set_binary_data(const char *data, size_t size, bool fin);

    bool get_data(const char **data, size_t *size) const;

    bool finished() const;
    
    ...
};
```
#### 1. opcode

协议中几种我们会接触到的数据包类型：
- WebSocketFrameText
- WebSocketFrameBinary
- WebSocketFramePing
- WebSocketFramePong

一般我们发送数据的时候用的是前两种（**文本**和**二进制**），无需手动指定**opcode**，而如果需要手动发送**PING**包时则需要通过``bool set_opcode(int opcode)``指定为**PING**包；发送完PING包之后根据**WebSocket**协议，对方会给我们回一个**PONG**包，我们会在``process()``里拿到。

#### 2. masking_key

**WebSocket**协议的文本和二进制数据都需要经过一个掩码加密，默认框架会随机生成，也可以通过``void set_masking_key(uint32_t masking_key)``手动指定。

#### 3. data

数据包括两种：
- **文本**，通过``set_text_data()``这类接口设置；
- **二进制**，通过``set_binary_data()``这类接口设置；

注意这些均为**非拷贝接口**，消息在发出之前需要用户来保证data在内存的生命周期；

这两类接口都有一个带``bool fin``参数的接口，表示本消息是否finish。因为**WebSocket**协议的数据包允许分段传输，如果你要发送一个完整的消息想分多次发送，则可以使用带``bool fin``的接口，并且把``fin``值设置为``false``。

#### 4. callback

只要消息发送完毕，就会回到我们创建task时传入的回调函数，此时我们得知消息是否发送成功。

一个简单的例子：

```cpp
void send_callback(WFWebSocketTask *task)
{
    if (task->get_state() != WFT_STATE_SUCCESS)
        fprintf(stderr, "Task send error: %d\n", task->get_error());
}
```

# 收消息

每次收到server发来的消息，``process()``都会被调起。如何在收到文本数据之后把数据打印出来？

一个简单的例子：

```cpp
void process(WFWebSocketTask *task)
{
    const char *data;
    size_t size;

    if (task->get_msg()->get_opcode() == WebSocketFrameText)
    {
        task->get_msg()->get_data(&data, &size);
        ...
    }
}
```

#### 1. 参数

``process()``函数里拿到的参数``WFWebSocketTask *task``，与callback回调函数里拿到的类型是一样的，因此用法也非常类似：

- 可以通过``get_msg()``拿到对应的数据，也就是上述的``WebSocketFrame``；
- 可以通过msg上的接口``get_opcode()``判断是什么类型的数据包，``process()``可能收到的数据包类型包括：**WebSocketFrameText**、**WebSocketFrameBinary**、**WebSocketFramePong**、**WebSocketFrameConnectionClose**；

#### 2. data

无论是**文本**还是**二进制**，都由``bool get_data(const char **data, size_t *size) const``拿收到的数据。

#### 3. fin

由于数据可以分段发送，因此我们可以通过``bool finished() const``判断该完整的消息是否结束。如果没有结束，则用户需要自行把data里的数据拷走，等消息结束之后进行完整消息的处理。

更多接口细节可以查看[websocket_parser.h ](/src/protocol/websocket_parser.h)

# 连接关闭

#### 1. 主动关闭

根据**WebSocket**协议，用户需要发起一个**close**包已告诉对方以示断开连接。

一个简单的例子：

```cpp
WFFacilities::WaitGroup wg(1);

WFWebSocketTask *task = client.create_close_task([&wg](WFWebSocketTask *task) {
    wg.done();
});

task->start();
wait_group.wait();
```

这里发起了一个close任务，由于close是异步的，因此在``task->start()``之后当前线程会退出，我们在当前线程结合一个了``wait_group``进行不占线程的阻塞，并在close任务的回调函数里唤醒，然后当前线程就可以安全调用``client.deinit()``、删除client实例以及退出了。

需要注意的是，如果不主动发起close任务，直接删除client实例，那么底层使用的那个网络连接还会存在，直到超时或其他原因断开；
而``client.deinit()``是个等待内部网络资源完全释放的同步接口，需要手动调用，以保证程序退出前client的所有资源安全释放。

#### 2. 被动关闭

如果连接被意外关闭(比如设置了keep_alive_timeout，连接已经断了我们并不会给对方发**WebSocketFrameConnectionClose**)，或由于其他意外连接被断开，对方没有发**WebSocketFrameConnectionClose**，那么我们可以在一个``close()``函数上获得这个事件。

我们可以在构造WebSocketClient时通过第二个函数传递进去，如下：

```
void close()
{
    // connection is closed
}

WebSocketClient client(process, close);
```

注意：无论是**主动关闭**还是**被动关闭**，只要构造client时传递了``close()``函数，那么连接关闭时``close()``都会被调用，也就是说，用户主动调用client.deinit()之后也会调用``close()``。

当然，如果连接被动关闭，那么**下一个任务发出时，内部依然会自动重建连接**，无需用户感知。所以``close()``函数只是用于让用户知道被断了，如果服务正常只是连接被断，用户无需做任何干预。

# WebSocketClient的参数

``WebSocketClient``的init函数有两个，除了刚才介绍的传入URL函数的接口以外，还可以传入client的参数：

```cpp
class WebSocketClient
{
public:
    int init(const std::string& url);
    int init(const struct WFWebSocketParams *params);
    ...
```

使用时记得用默认参数初始化一下：
```cpp
struct WFWebSocketParams params = WEBSOCKET_PARAMS_DEFAULT;
params.url = "ws://127.0.0.1:80";
params.sec_protocol = "chat";
                                                         
WebSocketClient client(process);
client.init(&params);
...
```

其中，参数的定义如下：

```cpp
struct WFWebSocketParams
{
    const char *url;         // 目标URL
    int idle_timeout;        // client第一次连接上之后可接受的空闲时间，超过idle_timeout没有数据过来会自动断开。默认：不断开。单位：毫秒
    int keep_alive_timeout;  // client保持长连接的时间，超过keep_alive_timeout没有数据过来会自动断开。默认：不断开。单位：毫秒
    int ping_interval;       // client自动发ping的时间间隔，用于做心跳，保持与远端的连接。默认：-1，不自动发ping(功能开发中)
    size_t size_limit;       // 每个数据包的大小限制，超过的话会拿到错误码1009(WSStatusCodeTooLarge)。默认：不限制
    bool random_masking_key; // WebSocket协议中数据包的掩码，框架帮每次自动随机生成一个。默认：自动生成
    const char *sec_protocol;// 应用层的Sec-Websocket-Protocol字段
    const char *sec_version; // 应用层的Sec-Websocket-Version字段
};
```

如果只使用URL调用init()，则会使用默参数。

# WFWebSocketTask的参数

task除了上述常用的``get_msg()``接口以外，可以设置一些参数，比如发送超时send_timeout：

```
    WFWebSocketTask *task = client.create_websocket_task(process);
    task->set_send_timeout(5000); // 单位：毫秒
    task->start();
```

# 进阶版：注意事项！

<img src="https://raw.githubusercontent.com/wiki/holmes1412/holmes1412/websocket_connect_close.png" width = "350" height = "270" alt="websocket_connect_close"/> <img src="https://raw.githubusercontent.com/wiki/holmes1412/holmes1412/websocket_read_write.png" width = "380" height = "300" alt="websocket_read_write"/>

#### 1. 与Workflow原有用法的差异

由于**WebSocket**协议是**Workflow**中首个实现的双工通信协议，因此有些差异是必须强调的：

1. **WebSocket**协议的收发都是使用**poller**线程，因此websocket_cli用户需要把**poller**线程数改大点，同理可以把**handler**线程数改小。参考：[about-config.md](/docs/about-config.md)
2. **process**函数中所有的消息都是由同一个线程串行执行的；
3. 回调函数**callback**的执行不一定在同一个线程；

#### 2. 连接的生命周期

只有在第一个任务发出的时候，连接才会真正被建立。因此如果只希望监听server而没有写消息需求的用户依然需要手动发一个**PING**，让内部建立连接。可以通过client的``create_ping_task()``接口创建一个**PING** task，该回调函数里可以通过**state**判断连接是否可用，如果等于**WFT_STATE_SUCCESS**,则表示``process()``里已经随时可以接收server来的消息了。

如果连接内部被断开，内部会伴随下一个请求自动重连，所以``close()``被调起时并不需要我们做什么。

client调用``deinit()``之后，可以重新调用``init()``继续使用。一般来说只有程序退出时才需要调用client的``deinit()``。

以下是一个连接在task1发出时才真正建立，而task2被断开后被调用到用的close，而之后继续发task3内部回重建连接，最后client主动deinit()去关闭连接的生命周期图示：

```
[client.init()]------->------------------->---------[client.deinit()]
                  [task1]-[task2]                    |(主动关)
                  [conn]---->----[close]             |
                                 ^                   |
                                 |        [task3]    V
                                 |        [conn]-->--[close]
                                 |
                             (被对方关)
```

#### 3. 时序性保证

[**发消息**]

消息发送顺序取决于发送任务调起的顺序。因此发消息保序有两种方式：
- 可以把要发送的任务串到一个series里做串行的保证
- 也可以在上一个任务的callback里发起下一个任务

但如果没有保证顺序发送的需求，那么往外发的``WFWebSocketTask``也可以被放到任何一个任务流图里，随具体业务逻辑顺序调起。

[**收消息**]

用于收消息的``process()``函数是保证被按收包顺序调起的，且保证前一个消息的process执行完毕，下一个process才会调起，因此用户无需担心收消息的顺序问题。

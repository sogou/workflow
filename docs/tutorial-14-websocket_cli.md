# Workflow第一个双工通信客户端：websocket_cli

# 示例代码

[tutorial-14-websocket_cli.cc](/tutorial/tutorial-14-websocket_cli.cc)

# 关于websocket_cli

这是一个可以收发**WebSocket**协议的client，也是第一个在**Workflow**上实现的双工通信协议。

运行方式：**./websocket_cli \<URL\>**

URL格式：**ws://host:port**

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

构造client时需要传入``process()``函数，这是我们收消息的处理函数，类型为：``std::function<void (WFWebSocketTask *)>;``，与**Workflow**其他``process()``的语义类似。

``init()``中需要传入**URL**，如果**UR**L非法，则``init()``会返回-1表示**URL**解析失败。

然后就可以通过client创建任务了，用法与**Workflow**其他协议类似：

```cpp
WFWebSocketTask *task = client.create_websocket_task(callback);
WebSocketFrame *msg = text_task->get_msg();
msg->set_text_data("This is Workflow websocket client.");
task->start();
```

我们通过``create_websocket_task()``的接口创建一个要往外发的任务，并传入回调函数**callback**。task可以通过``get_msg()``接口拿到要发送的消息体，我们往消息体里填入要发送的数据。因为**WebSocket**协议支持**文本**和**二进制**的数据，所以我们使用``set_text_data()``接口，表示传入的是文本消息。最后把任务**start**起来。task相关的具体接口可以查看：[WFChannel.h](/src/factory/WFChannel.h)

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

    bool is_finish() const;
    
    ...
};
```
#### 1. opcode

协议中几种我们会接触到的数据包类型：
- WebSocketFrameText
- WebSocketFrameBinary
- WebSocketFramePing
- WebSocketFramePong

一般我们发送数据的时候用的是前两种（**文本**和**二进制**），无需手动指定**opcode**，而如果需要手动发送**PING**包时则需要通过``bool set_opcode(int opcode);``指定为**PING**包；发送完PING包之后根据**WebSocket**协议，对方会给我们回一个**PONG**包，我们会在``process()``里拿到。

#### 2. masking_key

**WebSocket**协议的文本和二进制数据都需要经过一个掩码加密，用户可以不填，也可以通过``void set_masking_key(uint32_t masking_key);``手动指定；

#### 3. data

数据包括两种：
- **文本**，通过``set_text_data()``这类接口设置；
- **二进制**，通过``set_binary_data()``这类接口设置；

注意这些均为**非拷贝接口**，消息在发出之前需要用户来保证data在内存的生命周期；

这两类接口都有一个带``bool fin``参数的接口，表示本消息是否finish。因为**WebSocket**协议的数据包允许分段传输，如果你要发送一个完整的消息想分多次发送，则可以使用带``bool fin``的接口，并且把``fin``值设置为``false``。

#### 4. callback

只要消息发送完毕，就会回到我们创建task时传入的回调函数，此时我们得知消息是否发送成功。一个简单的例子：

```cpp
void send_callbakc(WFWebSocketTask *task)
{
    if (task->get_state() != WFT_STATE_SUCCESS)
        fprintf(stderr, "Task send error: %d\n", task->get_error());
}
```

# 收消息

每次收到server发来的消息，``process()``都会被调起。如何在收到文本数据之后把数据打印出来？一个简单的例子：

```cpp
void process(WFWebSocketTask *task)
{
    const char *data;
    size_t size;

    if (task->get_state() == WFT_STATE_SUCCESS &&
        task->get_msg()->get_opcode() == WebSocketFrameText)
    {
        task->get_msg()->get_data(&data, &size);
        ...
    }
}
```

#### 1. 参数

``process()``函数里拿到的参数``WFWebSocketTask *task``，与callback回调函数里拿到的类型是一样的，因此用法也非常类似：
- 可以通过``task->get_state()``和``task->get_error()``拿到任务的状态，只有``WFT_STATE_SUCCESS``的情况下才可以使用里边的数据；
- 可以通过``get_msg()``拿到对应的数据，也就是上述的``WebSocketFrame``；
- 可以通过msg上的接口``get_opcode()``判断是什么类型的数据包，``process()``可能收到的数据包类型包括：**WebSocketFrameText**、**WebSocketFrameBinary**、**WebSocketFramePong**。

#### 2. data

无论是**WebSocketFrameText**还是**WebSocketFrameBinary**，都由``bool get_data(const char **data, size_t *size) const;``拿收到的数据；

#### 3. fin

由于数据可以分段发送，因此我们可以通过``bool is_finish() const;``判断该完整的消息是否结束。如果没有结束，则用户需要自行把data里的数据拷走，等消息结束之后进行完整消息的处理；

更多细节接口可以查看[websocket_parser.h ](src/protocol/websocket_parser.h）

# 进阶版：Workflow用户的注意事项

// 都会在一个线程里执行
// poller线程需要改大

# websocket_cli的参数

# 关于client的关闭


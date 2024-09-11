# Redis订阅模式

## 示例代码
[tutorial-18-redis_subscriber.cc](/tutorial/tutorial-18-redis_subscriber.cc)

## 创建订阅客户端和任务
在Workflow中，一个客户端网络任务通常是向服务端发出一个请求并接收一个回复，而Redis订阅任务不同，它会先发出一个订阅请求，然后源源不断地接收服务端推送过来的消息，在这个过程中，客户端还可以新增或取消channels、patterns。

用于实现Redis订阅功能的任务是`WFRedisSubscribeTask`，与普通的Redis任务不同，它不从任务工厂产生，而是需要使用`WFRedisSubscriber`来创建。例如

```cpp
WFRedisSubscriber suber;

if (suber.init(url) != 0)
{
    std::cerr << "Subscriber init failed " << strerror(errno) << std::endl;
    exit(1);
}

// ...

WFRedisSubscribeTask *task;
task = suber.create_subscribe_task(channels, extract, callback);

task->set_watch_timeout(1000000); // 1000秒
task->start();

// 这里可以使用task的相关接口改变订阅内容
// ...

task->release();
suber.deinit();
```

初始化`WFRedisSubscriber`需要使用`Redis URL`，这与普通Redis任务相同，不再赘述。创建订阅任务时，需要提供三个参数

- channels/patterns: 一个或多个被订阅的channel(subscribe)或pattern(psubscribe)
- extract: 收到服务端推送消息时的处理函数
- callback: 任务结束后的回调函数

这个例子中为`watch_timeout`设置了一个很长的时间，若这个时间较短，且服务端长时间未推送消息，则连接会因为超时而断开，订阅任务也会直接失败，请根据实际情况合理设置。

当任务处理完成后，需要通过`task->release()`来释放这个任务，这也是与其他任务的一个不同之处。

## 处理订阅消息
服务端推送的消息由创建任务时指定的`extract`函数处理。后续描述中，subscribe对应channel，psubscribe对应pattern。

1. 服务端推送的消息格式是具有三个元素的数组，第一个元素是字符串"message"或"pmessage"，第二个元素是该消息的channel或pattern的名称，第三个元素是消息的内容。
2. subscribe或psubscribe请求的回复是具有三个元素的数组，第一个元素是字符串"subscribe"或"psubscribe"，第二个元素是channel或pattern的名称，第三个元素是当前通过subscribe或psubscribe命令已经订阅了多少个channel或pattern，是一个整数。如果一个请求订阅了多个channel或pattern，会有多个回复。
3. unsubscribe或punsubscribe请求的回复是具有三个元素的数组，格式与订阅命令相似。当取消订阅但不指定channel或pattern时，表示取消所有该类型的订阅，对于所有已经订阅的channel或pattern，返回一个回复消息。若当前类型未订阅任何channel或pattern，则返回一个消息，其中名称部分为nil。

更多详情可参阅redis文档。

处理消息的一个示例如下，简单地将内容打印到标准输出

```cpp
void extract(WFRedisSubscribeTask *task)
{
	auto *resp = task->get_resp();
	protocol::RedisValue value;

	resp->get_result(value);

	if (value.is_array())
	{
		for (size_t i = 0; i < value.arr_size(); i++)
		{
			if (value[i].is_string())
				std::cout << value[i].string_value();
			else if (value[i].is_int())
				std::cout << value[i].int_value();
			else if (value[i].is_nil())
				std::cout << "nil";
			else
				std::cout << "Unexpected value in array!";

			std::cout << "\n";
		}
	}
	else
		std::cout << "Unexpected value!\n";
}
```

## 改变订阅内容
在任务过程中，可以通过下述接口新增或取消订阅，注意在带有channels或patterns参数的接口中，请勿传入空数组。

```cpp
// ...

task->start();

// 新增订阅一组channels
task->subscribe(channels);

// 取消订阅一组channels
task->unsubscribe(channels);

// 取消订阅所有channels
task->unsubscribe();

// 新增订阅一组patterns
task->psubscribe(patterns);

// 取消订阅一组patterns
task->punsubscribe(patterns);

// 取消订阅所有patterns
task->punsubscribe();

task->release();
```

当所有channels和patterns都被取消订阅后，任务会直接结束，此后不能再新增订阅，请注意该细节。也可以直接通过`task->quit()`来主动结束任务。

此外，订阅模式下可以通过`task->ping()`或`task->ping(message)`向Redis服务器发起`ping`请求。当任务设置了较小的`watch_timeout`，但服务端可能长时间没有消息推送时，通过定时发出`ping`请求可以令服务端推送`pong`响应，此时任务便不会因为超时而失败。

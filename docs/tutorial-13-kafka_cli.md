# 异步Kafka客户端：kafka_cli
# 示例代码

[tutorial-13-kafka_cli.cc](../tutorial/tutorial-13-kafka_cli.cc)

# 关于编译选项

在workflow中，你可以使用第三方库比如librdkafka，也可使用自带的kafka client，因此它对kafka协议的支持是独立的。

通过命令make KAFKA=y 编译独立的类库支持kafka协议，系统需要预先安装[zlib](https://github.com/madler/zlib.git),[snappy](https://github.com/google/snappy.git),[lz4(>=1.7.5)](https://github.com/lz4/lz4.git),[zstd](https://github.com/facebook/zstd.git)等第三方库。

# 关于kafka_cli

这是一个kafka client，根据不同的输入参数，完成kafka的消息生产(produce)、消息消费(fetch)、元数据获取(meta)等。

编译时需要在tutorial目录中执行编译命令make KAFKA=y。

该程序从命令行读取一个kafka broker服务器地址和本次任务的类型(produce/fetch/meta)：

./kafka_cli \<broker_url\> [p/c/m]

程序会在执行完任务后自动退出，一切资源完全回收。

其中broker_url可以有多个url组成，多个url之间以,分割

- 形式如：kafka://host:port,kafka://host1:port...
- port默认为9092;
- 如果用户在这一层有upstream选取需求，可以参考[upstream文档](../docs/about-upstream.md)。

Kafka broker_url示例：

kafka://127.0.0.1/

kafka://kafka.host:9090/

kafka://10.160.23.23:9000,10.123.23.23,kafka://kafka.sogou

# 创建并启动Kafka任务

由于Kafka需要保存broker、meta和group之类的全局信息，因此建议用户使用WFKafkaClient这个二级工厂来创建kafka任务
~~~cpp
using kafka_callback_t = std::function<void (WFKafkaTask *)>;

WFKafkaTask *create_kafka_task(const std::string& query, int retry_max, kafka_callback_t cb);

WFKafkaTask *create_kafka_task(int retry_max, kafka_callback_t cb);
~~~

用户有两种方式设置任务的详细信息：

1、在query中直接指定任务类型、topic等信息

使用示例如下：
~~~cpp
int main(int argc, char *argv[])
{
	...
	client = new WFKafkaClient();
	client->init(url);
	task = client->create_kafka_task("api=fetch&topic=xxx&topic=yyy", 3, kafka_callback);

	...
	task->start();
	...
}
~~~

2、在创建完WFKafkaTask之后，根据任务的类型先调用set_api_type设置，然后调用add接口准备输入，

关于二级工厂的更多接口，可以在[WFKafkaClient.h](../src/client/WFKafkaClient.h)中查看

比如针对produce任务，先创建KafkaRecord，然后调用set_key, set_value, add_header_pair等方法构建KafkaRecord，

接着调用add_produce_record添加record，关于KafkaRecord的更多接口，可以在[KafkaDataTypes.h](../src/protocol/KafkaDataTypes.h)中查看

针对fetch和meta任务，需要调用add_topic指定topic

其他包括callback、series、user_data等与workflow其他task用法类似。

使用示例如下：
~~~cpp
int main(int argc, char *argv[])
{
	...
	WFKafkaClient *client_fetch = new WFKafkaClient();
	client_fetch->init(url);
	task = client_fetch->create_kafka_task("api=produce&topic=xxx&topic=yyy", 3, kafka_callback);

	KafkaRecord record;
	record.set_key("key1", strlen("key1"));
	record.set_value(buf, sizeof(buf));
	record.add_header_pair("hk1", 3, "hv1", 3);
	task->add_produce_record("workflow_test1", -1, std::move(record));

	...
	task->start();
	...
}
~~~

# fetch任务

fetch任务支持消费者组模式和手动模式

1、消费者组模式

在初始化client的时候需要指定消费者组的名称

使用示例如下：
~~~cpp
int main(int argc, char *argv[])
{
	...
	WFKafkaClient *client_fetch = new WFKafkaClient();
	client_fetch->init(url, cgroup_name);
	task = client_fetch->create_kafka_task("api=fetch&topic=xxx&topic=yyy", 3, kafka_callback);

	...
	task->start();
	...
}
~~~

2、手动模型

无需指定消费者组，同时需要用户指定topic、partition和offset

使用示例如下：
~~~cpp
	client = new WFKafkaClient();
	client->init(url);
	task = client->create_kafka_task("api=fetch", 3, kafka_callback);

	KafkaToppar toppar;
	toppar.set_topic_partition("workflow_test1", 0);
	toppar.set_offset(0);
	task->add_toppar(toppar);
~~~

# 关于client的关闭

在消费者组模式下，client在关闭之前需要调用create_leavegroup_task创建leavegroup_task，

它会发送leavegroup协议包，否则会导致消费者组没有正确退出

# 处理kafka结果

处理结果的函数和其他的示例一样，既可以使用普通函数也可以使用std::function来处理结果
~~~cpp
void kafka_callback(WFKafkaTask *task)
{
	int state = task->get_state();
	int error = task->get_error();

	// handle error states
	...

	protocol::KafkaResult *result = task->get_result();
	result->fetch_records(records);

	for (auto &v : records)
	{
		for (auto &w: v)
		{
			const void *value;
			size_t value_len;
			w->get_value(&value, &value_len);
			printf("produce\ttopic: %s, partition: %d, status: %d, offset: %lld, val_len: %zu\n",
				   w->get_topic(), w->get_partition(), w->get_status(), w->get_offset(), value_len);
		}
	}
	...

	protocol::KafkaResult new_result = std::move(*task->get_result());
	if (new_result.fetch_records(records))
	{
		for (auto &v : records)
		{
			if (v.empty())
				continue;

			for (auto &w: v)
			{
				if (fp)
				{
                	const void *value;
					size_t value_len;
					w->get_value(&value, &value_len);
					fwrite(w->get_value(), w->get_value_len(), 1, fp);
				}
			}
		}
	}
	...
}
~~~

在这个callback中，task就是二级工厂产生的task，任务的结果集类型是protocol::KafkaResult。

结果集对象可以通过task->get_result()直接得到，获得结果。

在[KafkaResult.h](../src/protocol/KafkaResult.h)中可以看到KafkaResult的定义。

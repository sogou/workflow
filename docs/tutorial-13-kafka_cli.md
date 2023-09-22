# 异步Kafka客户端：kafka_cli
# 示例代码

[tutorial-13-kafka_cli.cc](/tutorial/tutorial-13-kafka_cli.cc)

# 编译

由于支持Kafka的多种压缩方式，因此系统需要预先安装[zlib](https://github.com/madler/zlib.git),[snappy](https://github.com/google/snappy.git),[lz4(>=1.7.5)](https://github.com/lz4/lz4.git),[zstd](https://github.com/facebook/zstd.git)等第三方库。

支持CMake和Bazel两种编译方式。

CMake：执行命令make KAFKA=y 编译独立的类库（libwfkafka.a和libwfkafka.so）支持kafka协议；cd tutorial; make KAFKA=y 可以编译kafka_cli

Bazel：执行bazel build kafka 编译支持kafka协议的类库；执行bazel build kafka_cli 编译kafka_cli


# 关于kafka_cli

这是一个kafka client，可以完成kafka的消息生产(produce)和消息消费(fetch)。

编译时需要在tutorial目录中执行编译命令make KAFKA=y或者在项目根目录执行make KAFKA=y tutorial。

该程序从命令行读取一个kafka broker服务器地址和本次任务的类型(produce/fetch)：

./kafka_cli \<broker_url\> [p/c]

程序会在执行完任务后自动退出，一切资源完全回收。

其中broker_url可以有多个url组成，多个url之间以,分割

- 形式如：kafka://host:port,kafka://host1:port... 或：**kafkas**://host:port,**kafkas**://host1:port代表使用SSL通信。
- port的默认值在普通TCP连接下是9092，SSL下为9093。
- "kafka://"前缀可以缺省。这时候使用默认使用TCL通信。
- 多个url，必须都采用TCP或都采用SSL。否则init函数返回-1，错误码为EINVAL。
- 如果用户在这一层有upstream选取需求，可以参考[upstream文档](../docs/about-upstream.md)。

Kafka broker_url示例：

kafka://127.0.0.1/

kafka://kafka.host:9090/

kafka://10.160.23.23:9000,10.123.23.23,kafka://kafka.sogou

kafkas://broker1.kafka.sogou,kafkas://broker2.kafka.sogou

错误的url示例（第一个broker为SSL，第二个broker非SSL）：

kafkas://broker1.kafka.sogou,broker2.kafka.sogou

# 实现原理和特性

kafka client内部实现上除了压缩功能外没有依赖第三方库，同时利用了workflow的高性能，在合理的配置和环境下，每秒钟可以处理几万次Kafka请求。

在内部实现上，kafka client会把一次请求按照内部使用到的broker分拆成并行parallel任务，每个broker地址对应parallel任务中的一个子任务，

这样可以最大限度的提升效率，同时利用workflow内部对连接的复用机制使得整体的连接数控制在一个合理的范围。

如果一个broker地址下有多个topic partition，为了提高吞吐，应该创建多个client，然后按照topic partition分别创建任务独立启动。


# 创建并启动Kafka任务

首先需要创建一个WFKafkaClient对象，然后调用init函数初始化WFKafkaClient对象，
~~~cpp
int init(const std::string& broker_url);

int init(const std::string& broker_url, const std::string& group);
~~~
其中broker_url是kafka broker集群的地址，格式可以参考上面的broker_url，

group是消费者组的group_name，用在基于消费者组的fetch任务中，如果是produce任务或者没有使用消费者组的fetch任务，则不需要使用此接口；

用消费者组的时候，可以设置heartbeat的间隔时间，时间单位是毫秒，用于维持心跳：
~~~cpp
void set_heartbeat_interval(size_t interval_ms);
~~~

后面再通过WFKafkaClient对象创建kafka任务
~~~cpp
using kafka_callback_t = std::function<void (WFKafkaTask *)>;

WFKafkaTask *create_kafka_task(const std::string& query, int retry_max, kafka_callback_t cb);

WFKafkaTask *create_kafka_task(int retry_max, kafka_callback_t cb);
~~~
其中query中包含此次任务的类型以及topic等属性，retry_max表示最大重试次数，cb为用户自定义的callback函数，当task执行完毕后会被调用，

接着还可以修改task的默认配置以满足实际需要，详细接口可以在[KafkaDataTypes.h](../src/protocol/KafkaDataTypes.h)中查看
~~~cpp
KafkaConfig config;
config.set_client_id("workflow");
task->set_config(std::move(config));
~~~
支持的配置选项描述如下：
配置名 | 类型 | 默认值 | 含义
------ | ---- | -------| -------
produce_timeout | int | 100ms | produce的超时时间
produce_msg_max_bytes | int | 1000000 bytes | 单个消息的最大长度限制
produce_msgset_cnt | int | int | 10000 | 一次通信消息集合的最大条数
produce_msgset_max_bytes | int | 1000000 bytes | 一次通信消息集合的最大长度限制
fetch_timeout | int | 100ms | fetch的超时时间
fetch_min_bytes | int | 1 byte | 一次fetch通信最小消息的长度
fetch_max_bytes | int | 50M bytes | 一次fetch通信最大消息的长度
fetch_msg_max_bytes | int | 1M bytes | 一次fetch通信单个消息的最大长度
offset_timestamp | long long int | -1 | 消费者组模式下，没有找到历史offset时，初始化的offset，-2表示最久，-1表示最新
session_timeout | int | 10s | 加入消费者组初始化时的超时时间
rebalance_timeout | int | 10s | 加入消费者组同步信息阶段的超时时间
produce_acks | int | -1 | produce任务在返回之前应确保消息成功复制的broker节点数，-1表示所有的复制broker节点
allow_auto_topic_creation | bool | true | produce时topic不存在时，是否自动创建topic
broker_version | char * | NULL | 指定broker的版本号，<0.10时需要手动指定
compress_type | int | NoCompress | produce消息的压缩类型
client_id | char * | NULL | 表示client的id
check_crcs | bool | false | fetch任务中是否校验消息的crc32
offset_store | int | 0 | 加入消费者组时，是否使用上次提交offset，1表示使用指定的offset，0表示优先使用上次提交
sasl_mechanisms | char * | NULL | sasl认证类型，目前支持plain和scram
sasl_username | char * | NULL | sasl认证所需的username
sasl_password | char * | NULL | sasl认证所需的password


最后就可以调用start接口启动kafka任务。

# produce任务

1、在创建并初始化WFKafkaClient之后，可以在query中直接指定topic等信息创建WFKafkaTask任务

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

2、在创建完WFKafkaTask之后，先通过调用set_key, set_value, add_header_pair等方法构建KafkaRecord，

关于KafkaRecord的更多接口，可以在[KafkaDataTypes.h](../src/protocol/KafkaDataTypes.h)中查看

然后应该通过调用add_produce_record添加KafkaRecord，关于更多接口的详细定义，可以在[WFKafkaClient.h](../src/client/WFKafkaClient.h)中查看

需要注意的是，add_produce_record的第二个参数partition，当>=0是表示指定的partition，-1表示随机指定partition或者调用自定义的kafka_partitioner_t

kafka_partitioner_t可以通过set_partitioner接口设置自定义规则。

使用示例如下：
~~~cpp
int main(int argc, char *argv[])
{
	...
	WFKafkaClient *client_fetch = new WFKafkaClient();
	client_fetch->init(url);
	task = client_fetch->create_kafka_task("api=produce&topic=xxx&topic=yyy", 3, kafka_callback);
	task->set_partitioner(partitioner);

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

3、produce还可以使用kafka支持的4种压缩协议，通过设置配置项来实现

使用示例如下：
~~~cpp
int main(int argc, char *argv[])
{
	...
	WFKafkaClient *client_fetch = new WFKafkaClient();
	client_fetch->init(url);
	task = client_fetch->create_kafka_task("api=produce&topic=xxx&topic=yyy", 3, kafka_callback);

	KafkaConfig config;
	config.set_compress_type(Kafka_Zstd);
	task->set_config(std::move(config));

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

1、手动模式

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

2、消费者组模式

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

3、offset的提交

在消费者组模式下，用户消费消息后，可以在callback函数中，通过创建commit任务来自动提交消费的记录，使用示例如下：
~~~cpp
void kafka_callback(WFKafkaTask *task)
{
	...
	commit_task = client.create_kafka_task("api=commit", 3, kafka_callback);

	...
	commit_task->start();
	...
}
~~~


# 关于client的关闭

在消费者组模式下，client在关闭之前需要调用create_leavegroup_task创建leavegroup_task，

它会发送leavegroup协议包，如果没有启动leavegroup_task，会导致消费者组没有正确退出，触发这个组的rebalance。


# 处理kafka结果

消息的结果集的数据结构是KafkaResult，可以通过调用WFKafkaTask的get_result()接口获得，

然后调用KafkaResult的fetch_record接口可以将本次task相关的record取出来，它是一个KafkaRecord的二维vector，

第一维是topic partition，第二维是某个topic partition下对应的KafkaRecord，

在[KafkaResult.h](../src/protocol/KafkaResult.h)中可以看到KafkaResult的定义
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

# 认证
认证信息需要在配置中设置，以sasl为例:
~~~cpp
int main(int argc, char *argv[])
{
	...
	client = new WFKafkaClient();
	client->init(url);

	task = client->create_kafka_task("api=fetch&topic=xxx&topic=yyy", 3, kafka_callback);
	config.set_sasl_username("fetch");
	config.set_sasl_password("fetch-secret");
	config.set_sasl_mech("SCRAM-SHA-256");
	task->set_config(std::move(config));

	...
	task->start();
	...
}
~~~

# Asynchronous Kafka Client: kafka_cli

# Sample Codes

[tutorial-13-kafka_cli.cc](/tutorial/tutorial-13-kafka_cli.cc)

# About Compiler

Because of supporting multiple compression methods of Kafka, [zlib](https://github.com/madler/zlib.git), [snappy](https://github.com/google/snappy.git), [lz4(>=1.7.5)](https://github.com/lz4/lz4.git), [zstd](https://github.com/facebook/zstd.git) and other third-party libraries are used in the compression algorithms in the Kafka protocol, and they must be installed before the compilation.

It supports both CMake and Bazel for compiling.

CMake: You can use **make KAFKA=y** to compile a separate library for Kafka protocol(libwfkafka.a和libwfkafka.so) and use **cd tutorial; make KAFKA=y** to compile kafka_cli.

Bazel: You can use **bazel build kafka** to compile a separate library for Kafka protocol and use **bazel build kafka_cli** to compile kafka_cli.


# About kafka_cli

Kafka_cli is a kafka client for producing and fetching messages in Kafka. 

When you compile the source codes, type the command **make KAFKA=y** in the **tutorial** directory or type the command **make KAFKA=y tutorial** in the root directory of the project.

The program then reads kafka broker server addresses and the current task type (produce/fetch) from the command line:

./kafka_cli \<broker_url> [p/c]

The program exists automatically after all the tasks are completed, and all the resources will be completedly freed.

In the command, the broker_url may contain several urls seperated by comma(,).

- For instance, kafka://host:port,kafka://host1:port...
- The default value is 9092;
- If you want to use upstream policy at this layer, please refer to [upstream documents](/docs/en/about-upstream.md).

The following are several Kafka broker_url samples:

kafka://127.0.0.1/

kafka://kafka.host:9090/

kafka://10.160.23.23:9000,10.123.23.23,kafka://kafka.sogou

# Principles and Features

Kafka client has no third-party dependencies internally except for the libraries used in the compression. With the high performance of Workflow, When properly configured and in fair environments, tens of thousands of Kafka requests can be processed in one second.

Internally, a Kafka client divides each request into parallel tasks according to the brokers used. In parallel tasks, there is one sub-task for each broker address.

In this way, the efficiency is maximized. Besides, the connection reuse mechanism in the Workflow ensures that the total number of connections is kept within a reasonable range.

If there are multiple topic partitions under one broker address, you may create multiple clients and then create and start separate tasks for each topic partition to increase the throughput.

# Creating and Starting Kafka Tasks

To create and start a Kafka task, create a **WFKafkaClient** first and then call **init** to initialize that **WFKafkaClient**.

~~~cpp
int init(const std::string& broker_url);

int init(const std::string& broker_url, const std::string& group);
~~~

In the above code snippet, **broker_url** means the address of the kafka broker cluster. Its format is the same as the broker_url in the above section.

**group** means the group_name of a consumer group, which is used for the consumer group in a fetch task. In the case of produce tasks or fetch tasks without any consumer groups, do not use this interface.

For a consumer group, you can specify the heartbeat interval in milliseconds to keep the heartbeats.

~~~cpp
void set_heartbeat_interval(size_t interval_ms);
~~~

Then you can create a Kafka task with that **WFKafkaClient**.

~~~cpp
using kafka_callback_t = std::function<void (WFKafkaTask *)>;

WFKafkaTask *create_kafka_task(const std::string& query, int retry_max, kafka_callback_t cb);

WFKafkaTask *create_kafka_task(int retry_max, kafka_callback_t cb);
~~~

In the above code snippet, **query** includes the type of the task, the topic and other properties. **retry_max** means the maximum number of retries. **cb** is the user-defined callback function, which will be called after the task is completed. 

You can also change the default settings of the task to meet the requirements. For details, refer to [KafkaDataTypes.h](/src/protocol/KafkaDataTypes.h).

~~~cpp
KafkaConfig config;
config.set_client_id("workflow");
task->set_config(std::move(config));
~~~

The supported configuration items are described below: 

Item name | Type | Default value | Description  
------ | ---- | -------| -------  
produce_timeout | int | 100ms | Maximum time for produce. 
produce_msg_max_bytes | int | 1000000 bytes | Maximum length for one message. 
produce_msgset_cnt | int | 10000 | Maximun numbers of messges in one communication set 
produce_msgset_max_bytes | int | 1000000 bytes | Maximum length of messages in one communication. 
fetch_timeout | int | 100ms | Maximum timeout for fetch. 
fetch_min_bytes | int | 1 byte | Minimum length of messages in one fetch communication. 
fetch_max_bytes | int | 50M bytes | Maximum length of messages in one fetch communication. 
fetch_msg_max_bytes | int | 1M bytes | Maximum length of one single message in a fetch communication. 
offset_timestamp | long long int | -1 | Initialized offfset in the consumer group mode when there is no offset history. -2 means the oldest offset; -1 means the latest offset. 
session_timeout | int | 10s | Maximum initialization timeout for joining a consumer group. 
rebalance_timeout | int | 10s | Maximum timeout for synchronizing a consumer group information after a client joins the consumer group. 
produce_acks | int | -1 | Number of brokers to ensure the successful replication of a message before the return of a produce task. -1 indicates all replica brokers. 
allow_auto_topic_creation | bool | true | Flag for controlling whether a topic is created automatically for the produce task if it does not exist. 
broker_version | char * | NULL | Version number for brokers, which should be manually specified when the version number is smaller than 0.10. 
compress_type | int | NoCompress | Compression type for produce messages. 
client_id | char * | NULL | Identifier of a client.  
check_crcs | bool | false | Flag for controlling whether to check crc32 in the messages for a fetch task. 
offset_store | int | 0 | When joining the consumer group, whether to use the last submission offset, 1 means to use the specified offset, and 0 means to use the last submission preferentially.
sasl_mechanisms | char * | NULL | Sasl certification type, currently only supports plain, and is on the ongoing development of sasl support.
sasl_username | char * | NULL | Username required for sasl authentication.
sasl_password | char * | NULL | Password required for sasl authentication.


After configuring all the parameters, you can call **start** interface to start the Kafka task.

# About Produce Tasks

1\. After you create and initialize a **WFKafkaClient**, you can specify the topic or other information in the **query** to create **WFKafkaTask** tasks.

For example:

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

2\. After the **WFKafkaTask** is created, call **set_key**, **set_value**, **add_header_pair** and other methods to build a **KafkaRecord**. 

For information about more interfaces on **KafkaRecord**, refer to [KafkaDataTypes.h](/src/protocol/KafkaDataTypes.h).

Then you can call **add_produce_record** to add a **KafkaRecord**. For the detailed definitions of the interfaces, refer to [WFKafkaClient.h](/src/client/WFKafkaClient.h).

The second parameter **partition** in **add_produce_record**, >=0 means the specified **partition**; -1 means that the **partition** is chosen randomly or the user-defined **kafka_partitioner_t** is used. 

For **kafka_partitioner_t**, you can call the **set_partitioner** interface to specify the user-defined rules.

For example:

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

3\. You can use one of the four compressions supported by Kafka in the produce task by configuration. 

For example:

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

# About Fetch Tasks

You may use consumer group mode or manual mode for fetch tasks.

1\. Manual mode

In this mode, you do not need to specify consumer groups, but you must specify topic, partition and offset.

For example:

~~~cpp
	client = new WFKafkaClient();
	client->init(url);
	task = client->create_kafka_task("api=fetch", 3, kafka_callback);

	KafkaToppar toppar;
	toppar.set_topic_partition("workflow_test1", 0);
	toppar.set_offset(0);
	task->add_toppar(toppar);
~~~

2\. Consumer group mode

In this mode, you must specify the name of the consumer group when initializing a client.

For example:

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

3\. Committing offset

In the consumer group mode, after a message is consumed, you can create a commit task in the callback to automatically submit the consumption record. 

For example:

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

# Closing the Client

In the consumer group mode, before you close a client, you must call **create_leavegroup_task** to create a **leavegroup_task**.

This task will send a **leavegroup** packet. If no **leavegroup_task** is started, the group does not know that the client is leaving and will trigger rebalance.

# Processing Kafka Results

The data structure of the message result set is KafkaResult, and you can call **get_result()** in the **WFKafkaTask** to retrieve the results.

Then you can call the **fetch_record** in the **KafkaResult** to retrieve all records of the task. The record is a two-dimensional vector.

The first dimension is topic partition, and the second dimension is the **KafkaRecord** under that topic partition.

[KafkaResult.h](/src/protocol/KafkaResult.h) contains the definition of **KafkaResult**.

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

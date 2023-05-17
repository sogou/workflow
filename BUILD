config_setting(
	name = 'linux',
	constraint_values = [
		"@platforms//os:linux",
	],
	visibility = ['//visibility:public'],
)

cc_library(
	name = 'workflow_hdrs',
	hdrs = glob(['src/include/workflow/*']),
	includes = ['src/include'],
	visibility = ["//visibility:public"],
	linkopts = [
		'-lpthread',
		'-lssl',
		'-lcrypto',
	],
)
cc_library(
	name = 'common_c',
	srcs = [
		'src/kernel/mpoller.c',
		'src/kernel/msgqueue.c',
		'src/kernel/poller.c',
		'src/kernel/rbtree.c',
		'src/kernel/thrdpool.c',
		'src/util/crc32c.c',
		'src/util/json_parser.c',
	],
	hdrs = glob(['src/*/*.h']) + glob(['src/*/*.inl']),
	includes = [
		'src/kernel',
		'src/util',
	],
	copts = ['-std=gnu90'],
	visibility = ["//visibility:public"],
)
cc_library(
	name = 'common',
	srcs = [
		'src/client/WFDnsClient.cc',
		'src/factory/DnsTaskImpl.cc',
		'src/factory/FileTaskImpl.cc',
		'src/factory/WFGraphTask.cc',
		'src/factory/WFResourcePool.cc',
		'src/factory/WFMessageQueue.cc',
		'src/factory/WFTaskFactory.cc',
		'src/factory/Workflow.cc',
		'src/manager/DnsCache.cc',
		'src/manager/RouteManager.cc',
		'src/manager/WFGlobal.cc',
		'src/nameservice/WFDnsResolver.cc',
		'src/nameservice/WFNameService.cc',
		'src/protocol/DnsMessage.cc',
		'src/protocol/DnsUtil.cc',
		'src/protocol/SSLWrapper.cc',
		'src/protocol/PackageWrapper.cc',
		'src/protocol/dns_parser.c',
		'src/server/WFServer.cc',
		'src/kernel/CommRequest.cc',
		'src/kernel/CommScheduler.cc',
		'src/kernel/Communicator.cc',
		'src/kernel/Executor.cc',
		'src/kernel/SubTask.cc',
	] + select({
		':linux': [
			'src/kernel/IOService_linux.cc',
		],
		'//conditions:default': [
			'src/kernel/IOService_thread.cc',
		],
	}) + glob(['src/util/*.cc']),
	hdrs = glob(['src/*/*.h']) + glob(['src/*/*.inl']),
	includes = [
		'src/algorithm',
		'src/client',
		'src/factory',
		'src/kernel',
		'src/manager',
		'src/nameservice',
		'src/protocol',
		'src/server',
		'src/util',
	],
	deps = ['workflow_hdrs', 'common_c'],
	visibility = ["//visibility:public"],
)
cc_library(
	name = 'http',
	hdrs = [
		'src/protocol/HttpMessage.h',
		'src/protocol/HttpUtil.h',
		'src/protocol/http_parser.h',
		'src/factory/WFHttpServerTask.h',
		'src/server/WFHttpServer.h',
	],
	includes = [
		'src/protocol',
		'src/server',
	],
	srcs = [
		'src/factory/HttpTaskImpl.cc',
		'src/protocol/HttpMessage.cc',
		'src/protocol/HttpUtil.cc',
		'src/protocol/http_parser.c',
	],
	deps = [
		':common',
	],
	visibility = ["//visibility:public"],
)
cc_library(
	name = 'redis',
	hdrs = [
		'src/protocol/RedisMessage.h',
		'src/protocol/redis_parser.h',
		'src/server/WFRedisServer.h',
	],
	includes = [
		'src/protocol',
		'src/server',
	],
	srcs = [
		'src/factory/RedisTaskImpl.cc',
		'src/protocol/RedisMessage.cc',
		'src/protocol/redis_parser.c',
	],
	deps = [
		':common',
	],
	visibility = ["//visibility:public"],
)
cc_library(
	name = 'mysql',
	hdrs = [
		'src/client/WFMySQLConnection.h',
		'src/protocol/MySQLMessage.h',
		'src/protocol/MySQLMessage.inl',
		'src/protocol/MySQLResult.h',
		'src/protocol/MySQLResult.inl',
		'src/protocol/MySQLUtil.h',
		'src/protocol/mysql_byteorder.h',
		'src/protocol/mysql_parser.h',
		'src/protocol/mysql_stream.h',
		'src/protocol/mysql_types.h',
		'src/server/WFMySQLServer.h',
	],
	includes = [
		'src/protocol',
		'src/client',
		'src/server',
	],
	srcs = [
		'src/client/WFMySQLConnection.cc',
		'src/factory/MySQLTaskImpl.cc',
		'src/protocol/MySQLMessage.cc',
		'src/protocol/MySQLResult.cc',
		'src/protocol/MySQLUtil.cc',
		'src/protocol/mysql_byteorder.c',
		'src/protocol/mysql_parser.c',
		'src/protocol/mysql_stream.c',
	],
	deps = [
		':common',
	],
	visibility = ["//visibility:public"],
)

cc_library(
	name = 'upstream',
	hdrs = [
		'src/manager/UpstreamManager.h',
		'src/nameservice/UpstreamPolicies.h',
		'src/nameservice/WFServiceGovernance.h',
	],
	includes = [
		'src/manager',
		'src/nameservice',
	],
	srcs = [
		'src/manager/UpstreamManager.cc',
		'src/nameservice/UpstreamPolicies.cc',
		'src/nameservice/WFServiceGovernance.cc',
	],
	deps = [
		':common',
	],
	visibility = ["//visibility:public"],
)

cc_library(
	name = 'kafka_message',
	hdrs = [
		'src/factory/KafkaTaskImpl.inl',
		'src/protocol/KafkaDataTypes.h',
		'src/protocol/KafkaMessage.h',
		'src/protocol/KafkaResult.h',
		'src/protocol/kafka_parser.h',
	],
	includes = [
		'src/factory',
		'src/protocol',
	],
	srcs = [
		'src/factory/KafkaTaskImpl.cc',
		'src/protocol/KafkaMessage.cc',
	],
	copts = ['-fno-rtti'],
	deps = [
		':common',
	],
)

cc_library(
	name = 'kafka',
	hdrs = [
		'src/client/WFKafkaClient.h',
		'src/factory/KafkaTaskImpl.inl',
		'src/protocol/KafkaDataTypes.h',
		'src/protocol/KafkaMessage.h',
		'src/protocol/KafkaResult.h',
		'src/protocol/kafka_parser.h',
	],
	includes = [
		'src/client',
		'src/factory',
		'src/protocol',
	],
	srcs = [
		'src/client/WFKafkaClient.cc',
		'src/protocol/KafkaDataTypes.cc',
		'src/protocol/KafkaResult.cc',
		'src/protocol/kafka_parser.c',
	],
	deps = [
		':common',
		':kafka_message',
	],
	visibility = ["//visibility:public"],
	linkopts = [
		'-lsnappy',
		'-llz4',
		'-lz',
		'-lzstd',
	],
)

cc_library(
	name = 'consul',
	hdrs = [
		'src/client/WFConsulClient.h',
		'src/protocol/ConsulDataTypes.h',
	],
	includes = [ 
		'src/client',
		'src/factory',
		'src/protocol',
		'src/util',
	],
	srcs = [ 
		'src/client/WFConsulClient.cc',
	],
	deps = [
		':common',
		':http',
	],
	visibility = ["//visibility:public"],
)

cc_binary(
	 name = 'helloworld',
	 srcs = ['tutorial/tutorial-00-helloworld.cc'],
	 deps = [':http'],
)
cc_binary(
	 name = 'wget',
	 srcs = ['tutorial/tutorial-01-wget.cc'],
	 deps = [':http'],
)
cc_binary(
	 name = 'redis_cli',
	 srcs = ['tutorial/tutorial-02-redis_cli.cc'],
	 deps = [':redis'],
)

cc_binary(
	 name = 'wget_to_redis',
	 srcs = ['tutorial/tutorial-03-wget_to_redis.cc'],
	 deps = [':http', 'redis'],
)

cc_binary(
	 name = 'http_echo_server',
	 srcs = ['tutorial/tutorial-04-http_echo_server.cc'],
	 deps = [':http'],
)

cc_binary(
	 name = 'http_proxy',
	 srcs = ['tutorial/tutorial-05-http_proxy.cc'],
	 deps = [':http'],
)

cc_binary(
	 name = 'parallel_wget',
	 srcs = ['tutorial/tutorial-06-parallel_wget.cc'],
	 deps = [':http'],
)

cc_binary(
	 name = 'sort_task',
	 srcs = ['tutorial/tutorial-07-sort_task.cc'],
	 deps = [':common'],
)

cc_binary(
	 name = 'matrix_multiply',
	 srcs = ['tutorial/tutorial-08-matrix_multiply.cc'],
	 deps = [':common'],
)

cc_binary(
	 name = 'http_file_server',
	 srcs = ['tutorial/tutorial-09-http_file_server.cc'],
	 deps = [':http'],
)

cc_library(
	name = 'user_hdrs',
	hdrs = ['tutorial/tutorial-10-user_defined_protocol/message.h'],
	includes = ['tutorial/tutorial-10-user_defined_protocol'],
)

cc_binary(
	 name = 'server',
	 srcs = [
	 	  'tutorial/tutorial-10-user_defined_protocol/server.cc',
		  'tutorial/tutorial-10-user_defined_protocol/message.cc',
	 ],
	 deps = [':common', ':user_hdrs'],
)

cc_binary(
	 name = 'client',
	 srcs = [
	 	  'tutorial/tutorial-10-user_defined_protocol/client.cc',
		  'tutorial/tutorial-10-user_defined_protocol/message.cc',
	 ],
	 deps = [':common', ':user_hdrs'],
)

cc_binary(
	 name = 'graph_task',
	 srcs = ['tutorial/tutorial-11-graph_task.cc'],
	 deps = [':http'],
)

cc_binary(
	 name = 'mysql_cli',
	 srcs = ['tutorial/tutorial-12-mysql_cli.cc'],
	 deps = [':mysql'],
)

cc_binary(
	 name = 'kafka_cli',
	 srcs = ['tutorial/tutorial-13-kafka_cli.cc'],
	 deps = [':kafka', ':workflow_hdrs'],
)

cc_binary(
	 name = 'consul_cli',
	 srcs = ['tutorial/tutorial-14-consul_cli.cc'],
	 deps = [':consul'],
)

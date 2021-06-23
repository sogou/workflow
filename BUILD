cc_library(
	name = 'common',
	srcs = [
		'src/algorithm/DnsRoutine.cc',
		'src/client/WFDnsClient.cc',
		'src/factory/DnsTaskImpl.cc',
		'src/factory/WFGraphTask.cc',
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
		'src/protocol/dns_parser.c',
		'src/server/WFServer.cc',
		'src/kernel/CommRequest.cc',
		'src/kernel/CommScheduler.cc',
		'src/kernel/Communicator.cc',
		'src/kernel/Executor.cc',
		'src/kernel/IOService_linux.cc',
		'src/kernel/SubTask.cc',
		'src/kernel/mpoller.c',
		'src/kernel/msgqueue.c',
		'src/kernel/poller.c',
		'src/kernel/rbtree.c',
		'src/kernel/thrdpool.c',
	] + glob(['src/util/*.c']) + glob(['src/util/*.cc']),
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
	visibility = ["//visibility:public"],
)
cc_library(
	name = 'http',
	hdrs = [
		'src/protocol/HttpMessage.h',
		'src/protocol/HttpUtil.h',
		'src/protocol/http_parser.h',
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
		'src/factory/KafkaTaskImpl.cc',
		'src/protocol/KafkaDataTypes.cc',
		'src/protocol/KafkaMessage.cc',
		'src/protocol/KafkaResult.cc',
		'src/protocol/kafka_parser.c',
	],
	copts = ['-fno-rtti'],
	deps = [
		':common',
	],
	visibility = ["//visibility:public"],
)
#cc_binary(
#	 name = 'kafka_cli',
#	 srcs = ['tutorial/tutorial-13-kafka_cli.cc'],
#	 deps = [':kafka'],
#	 copts = ['-fno-rtti'],
#	 linkopts = [
#		 '-L/usr/local/lib',
#		 '-L/usr/local/lib64',
#		 '-lpthread',
#		 '-lssl',
#		 '-lcrypto',
#		 '-lsnappy',
#		 '-llz4',
#		 '-lz',
#		 '-lzstd',
#	 ],
#)

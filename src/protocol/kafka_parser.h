/*
  Copyright (c) 2020 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

	  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Authors: Wang Zhulei (wangzhulei@sogou-inc.com)
*/

#ifndef _KAFKA_PARSER_H_
#define _KAFKA_PARSER_H_

#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include "list.h"

enum
{
	KAFKA_UNKNOWN_SERVER_ERROR = -1,
	KAFKA_OFFSET_OUT_OF_RANGE = 1,
	KAFKA_CORRUPT_MESSAGE = 2,
	KAFKA_UNKNOWN_TOPIC_OR_PARTITION = 3,
	KAFKA_INVALID_FETCH_SIZE = 4,
	KAFKA_LEADER_NOT_AVAILABLE = 5,
	KAFKA_NOT_LEADER_FOR_PARTITION = 6,
	KAFKA_REQUEST_TIMED_OUT = 7,
	KAFKA_BROKER_NOT_AVAILABLE = 8,
	KAFKA_REPLICA_NOT_AVAILABLE = 9,
	KAFKA_MESSAGE_TOO_LARGE = 10,
	KAFKA_STALE_CONTROLLER_EPOCH = 11,
	KAFKA_OFFSET_METADATA_TOO_LARGE = 12,
	KAFKA_NETWORK_EXCEPTION = 13,
	KAFKA_COORDINATOR_LOAD_IN_PROGRESS = 14,
	KAFKA_COORDINATOR_NOT_AVAILABLE = 15,
	KAFKA_NOT_COORDINATOR = 16,
	KAFKA_INVALID_TOPIC_EXCEPTION = 17,
	KAFKA_RECORD_LIST_TOO_LARGE = 18,
	KAFKA_NOT_ENOUGH_REPLICAS = 19,
	KAFKA_NOT_ENOUGH_REPLICAS_AFTER_APPEND = 20,
	KAFKA_INVALID_REQUIRED_ACKS = 21,
	KAFKA_ILLEGAL_GENERATION = 22,
	KAFKA_INCONSISTENT_GROUP_PROTOCOL = 23,
	KAFKA_INVALID_GROUP_ID = 24,
	KAFKA_UNKNOWN_MEMBER_ID = 25,
	KAFKA_INVALID_SESSION_TIMEOUT = 26,
	KAFKA_REBALANCE_IN_PROGRESS = 27,
	KAFKA_INVALID_COMMIT_OFFSET_SIZE = 28,
	KAFKA_TOPIC_AUTHORIZATION_FAILED = 29,
	KAFKA_GROUP_AUTHORIZATION_FAILED = 30,
	KAFKA_CLUSTER_AUTHORIZATION_FAILED = 31,
	KAFKA_INVALID_TIMESTAMP = 32,
	KAFKA_UNSUPPORTED_SASL_MECHANISM = 33,
	KAFKA_ILLEGAL_SASL_STATE = 34,
	KAFKA_UNSUPPORTED_VERSION = 35,
	KAFKA_TOPIC_ALREADY_EXISTS = 36,
	KAFKA_INVALID_PARTITIONS = 37,
	KAFKA_INVALID_REPLICATION_FACTOR = 38,
	KAFKA_INVALID_REPLICA_ASSIGNMENT = 39,
	KAFKA_INVALID_CONFIG = 40,
	KAFKA_NOT_CONTROLLER = 41,
	KAFKA_INVALID_REQUEST = 42,
	KAFKA_UNSUPPORTED_FOR_MESSAGE_FORMAT = 43,
	KAFKA_POLICY_VIOLATION = 44,
	KAFKA_OUT_OF_ORDER_SEQUENCE_NUMBER = 45,
	KAFKA_DUPLICATE_SEQUENCE_NUMBER = 46,
	KAFKA_INVALID_PRODUCER_EPOCH = 47,
	KAFKA_INVALID_TXN_STATE = 48,
	KAFKA_INVALID_PRODUCER_ID_MAPPING = 49,
	KAFKA_INVALID_TRANSACTION_TIMEOUT = 50,
	KAFKA_CONCURRENT_TRANSACTIONS = 51,
	KAFKA_TRANSACTION_COORDINATOR_FENCED = 52,
	KAFKA_TRANSACTIONAL_ID_AUTHORIZATION_FAILED = 53,
	KAFKA_SECURITY_DISABLED = 54,
	KAFKA_OPERATION_NOT_ATTEMPTED = 55,
	KAFKA_KAFKA_STORAGE_ERROR = 56,
	KAFKA_LOG_DIR_NOT_FOUND = 57,
	KAFKA_SASL_AUTHENTICATION_FAILED = 58,
	KAFKA_UNKNOWN_PRODUCER_ID = 59,
	KAFKA_REASSIGNMENT_IN_PROGRESS = 60,
	KAFKA_DELEGATION_TOKEN_AUTH_DISABLED = 61,
	KAFKA_DELEGATION_TOKEN_NOT_FOUND = 62,
	KAFKA_DELEGATION_TOKEN_OWNER_MISMATCH = 63,
	KAFKA_DELEGATION_TOKEN_REQUEST_NOT_ALLOWED = 64,
	KAFKA_DELEGATION_TOKEN_AUTHORIZATION_FAILED = 65,
	KAFKA_DELEGATION_TOKEN_EXPIRED = 66,
	KAFKA_INVALID_PRINCIPAL_TYPE = 67,
	KAFKA_NON_EMPTY_GROUP = 68,
	KAFKA_GROUP_ID_NOT_FOUND = 69,
	KAFKA_FETCH_SESSION_ID_NOT_FOUND = 70,
	KAFKA_INVALID_FETCH_SESSION_EPOCH = 71,
	KAFKA_LISTENER_NOT_FOUND = 72,
	KAFKA_TOPIC_DELETION_DISABLED = 73,
	KAFKA_FENCED_LEADER_EPOCH = 74,
	KAFKA_UNKNOWN_LEADER_EPOCH = 75,
	KAFKA_UNSUPPORTED_COMPRESSION_TYPE = 76,
	KAFKA_STALE_BROKER_EPOCH = 77,
	KAFKA_OFFSET_NOT_AVAILABLE = 78,
	KAFKA_MEMBER_ID_REQUIRED = 79,
	KAFKA_PREFERRED_LEADER_NOT_AVAILABLE = 80,
	KAFKA_GROUP_MAX_SIZE_REACHED = 81,
	KAFKA_FENCED_INSTANCE_ID = 82,
};

enum
{
	Kafka_Unknown = -1,
	Kafka_Produce = 0,
	Kafka_Fetch = 1,
	Kafka_ListOffsets = 2,
	Kafka_Metadata = 3,
	Kafka_LeaderAndIsr = 4,
	Kafka_StopReplica = 5,
	Kafka_UpdateMetadata = 6,
	Kafka_ControlledShutdown = 7,
	Kafka_OffsetCommit = 8,
	Kafka_OffsetFetch = 9,
	Kafka_FindCoordinator = 10,
	Kafka_JoinGroup = 11,
	Kafka_Heartbeat = 12,
	Kafka_LeaveGroup = 13,
	Kafka_SyncGroup = 14,
	Kafka_DescribeGroups = 15,
	Kafka_ListGroups = 16,
	Kafka_SaslHandshake = 17,
	Kafka_ApiVersions = 18,
	Kafka_CreateTopics = 19,
	Kafka_DeleteTopics = 20,
	Kafka_DeleteRecords = 21,
	Kafka_InitProducerId = 22,
	Kafka_OffsetForLeaderEpoch = 23,
	Kafka_AddPartitionsToTxn = 24,
	Kafka_AddOffsetsToTxn = 25,
	Kafka_EndTxn = 26,
	Kafka_WriteTxnMarkers = 27,
	Kafka_TxnOffsetCommit = 28,
	Kafka_DescribeAcls = 29,
	Kafka_CreateAcls = 30,
	Kafka_DeleteAcls = 31,
	Kafka_DescribeConfigs = 32,
	Kafka_AlterConfigs = 33,
	Kafka_AlterReplicaLogDirs = 34,
	Kafka_DescribeLogDirs = 35,
	Kafka_SaslAuthenticate = 36,
	Kafka_CreatePartitions = 37,
	Kafka_CreateDelegationToken = 38,
	Kafka_RenewDelegationToken = 39,
	Kafka_ExpireDelegationToken = 40,
	Kafka_DescribeDelegationToken = 41,
	Kafka_DeleteGroups = 42,
	Kafka_ElectPreferredLeaders = 43,
	Kafka_IncrementalAlterConfigs = 44,
	Kafka_ApiNums,
};

enum
{
	Kafka_NoCompress,
	Kafka_Gzip,
	Kafka_Snappy,
	Kafka_Lz4,
	Kafka_Zstd,
};

enum
{
	KAFKA_FEATURE_APIVERSION = 1<<0,
	KAFKA_FEATURE_BROKER_BALANCED_CONSUMER = 1<<1,
	KAFKA_FEATURE_THROTTLETIME = 1<<2,
	KAFKA_FEATURE_BROKER_GROUP_COORD = 1<<3,
	KAFKA_FEATURE_LZ4 = 1<<4,
	KAFKA_FEATURE_OFFSET_TIME = 1<<5,
	KAFKA_FEATURE_MSGVER2 = 1<<6,
	KAFKA_FEATURE_MSGVER1 = 1<<7,
	KAFKA_FEATURE_ZSTD = 1<<8,
	KAFKA_FEATURE_SASL_GSSAPI = 1<<9,
	KAFKA_FEATURE_SASL_HANDSHAKE = 1<<10,
	KAFKA_FEATURE_SASL_AUTH_REQ = 1<<11,
};

enum
{
	KAFKA_OFFSET_AUTO,
	KAFKA_OFFSET_ASSIGN,
};

enum
{
	KAFKA_BROKER_UNINIT,
	KAFKA_BROKER_DOING,
	KAFKA_BROKER_INITED,
};

enum
{
	KAFKA_TIMESTAMP_EARLIEST = -2,
	KAFKA_TIMESTAMP_LATEST = -1,
	KAFKA_TIMESTAMP_UNINIT = 0,
};

enum
{
	KAFKA_OFFSET_UNINIT = -2,
	KAFKA_OFFSET_OVERFLOW = -1,
};

typedef struct __kafka_api_version
{
	short api_key;
	short min_ver;
	short max_ver;
} kafka_api_version_t;

typedef struct __kafka_api_t
{
	unsigned features;
	kafka_api_version_t *api;
	int elements;
} kafka_api_t;

typedef struct __kafka_parser
{
	int complete;
	size_t message_size;
	void *msgbuf;
	size_t cur_size;
	char headbuf[4];
	size_t hsize;
} kafka_parser_t;

enum __kafka_scram_state
{
	KAFKA_SASL_SCRAM_STATE_CLIENT_FIRST_MESSAGE,
	KAFKA_SASL_SCRAM_STATE_SERVER_FIRST_MESSAGE,
	KAFKA_SASL_SCRAM_STATE_CLIENT_FINAL_MESSAGE,
	KAFKA_SASL_SCRAM_STATE_CLIENT_FINISHED,
};

typedef struct __kafka_scram
{
	const void *evp;
	unsigned char *(*scram_h)(const unsigned char *d, size_t n,
							  unsigned char *md);
	size_t scram_h_size;
	enum __kafka_scram_state state;
	struct iovec cnonce;
	struct iovec first_msg;
	struct iovec server_signature_b64;
} kafka_scram_t;

typedef struct __kafka_sasl
{
	kafka_scram_t scram;
	char *buf;
	size_t bsize;
	int status;
} kafka_sasl_t;

typedef struct __kafka_config
{
	int produce_timeout;
	int produce_msg_max_bytes;
	int produce_msgset_cnt;
	int produce_msgset_max_bytes;
	int fetch_timeout;
	int fetch_min_bytes;
	int fetch_max_bytes;
	int fetch_msg_max_bytes;
	long long offset_timestamp;
	long long commit_timestamp;
	int session_timeout;
	int rebalance_timeout;
	long long retention_time_period;
	int produce_acks;
	int allow_auto_topic_creation;
	int api_version_request;
	int api_version_timeout;
	char *broker_version;
	int compress_type;
	int compress_level;
	char *client_id;
	int check_crcs;
	int offset_store;
	char *rack_id;

	char *mechanisms;
	char *username;
	char *password;
	int (*client_new)(void *conf, kafka_sasl_t *sasl);
	int (*recv)(const char *buf, size_t len, void *conf, void *sasl);
} kafka_config_t;

typedef struct __kafka_broker
{
	int node_id;
	int port;
	char *host;
	char *rack;
	int to_addr;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	short error;
	int status;
} kafka_broker_t;

typedef struct __kafka_partition
{
	short error;
	int partition_index;
	kafka_broker_t leader;
	int *replica_nodes;
	int replica_node_elements;
	int *isr_nodes;
	int isr_node_elements;
} kafka_partition_t;

typedef struct __kafka_meta
{
	short error;
	char *topic_name;
	char *error_message;
	signed char is_internal;
	kafka_partition_t **partitions;
	int partition_elements;
} kafka_meta_t;

typedef struct __kafka_topic_partition
{
	short error;
	char *topic_name;
	int partition;
	int preferred_read_replica;
	long long offset;
	long long high_watermark;
	long long low_watermark;
	long long last_stable_offset;
	long long log_start_offset;
	long long offset_timestamp;
	char *committed_metadata;
	struct list_head record_list;
} kafka_topic_partition_t;

typedef struct __kafka_record_header
{
	struct list_head list;
	void *key;
	size_t key_len;
	int key_is_moved;
	void *value;
	size_t value_len;
	int value_is_moved;
} kafka_record_header_t;

typedef struct __kafka_record
{
	void *key;
	size_t key_len;
	int key_is_moved;
	void *value;
	size_t value_len;
	int value_is_moved;
	long long timestamp;
	long long offset;
	struct list_head header_list;
	short status;
	kafka_topic_partition_t *toppar;
} kafka_record_t;

typedef struct __kafka_memeber
{
	char *member_id;
	char *client_id;
	char *client_host;
	void *member_metadata;
	size_t member_metadata_len;
	struct list_head toppar_list;
	struct list_head assigned_toppar_list;
} kafka_member_t;

typedef int (*kafka_assignor_t)(kafka_member_t **members, int member_elements,
								void *meta_topic);

typedef struct __kafka_group_protocol
{
	struct list_head list;
	char *protocol_name;
	kafka_assignor_t assignor;
} kafka_group_protocol_t;

typedef struct __kafka_cgroup
{
	struct list_head assigned_toppar_list;
	short error;
	char *error_msg;
	kafka_broker_t coordinator;
	char *leader_id;
	char *member_id;
	kafka_member_t **members;
	int member_elements;
	int generation_id;
	char *group_name;
	char *protocol_type;
	char *protocol_name;
	struct list_head group_protocol_list;
} kafka_cgroup_t;

typedef struct __kafka_block
{
	void *buf;
	size_t len;
	int is_moved;
} kafka_block_t;


#ifdef __cplusplus
extern "C"
{
#endif

int kafka_parser_append_message(const void *buf, size_t *size,
								kafka_parser_t *parser);

void kafka_parser_init(kafka_parser_t *parser);
void kafka_parser_deinit(kafka_parser_t *parser);

void kafka_topic_partition_init(kafka_topic_partition_t *toppar);
void kafka_topic_partition_deinit(kafka_topic_partition_t *toppar);

void kafka_cgroup_init(kafka_cgroup_t *cgroup);
void kafka_cgroup_deinit(kafka_cgroup_t *cgroup);

void kafka_block_init(kafka_block_t *block);
void kafka_block_deinit(kafka_block_t *block);

void kafka_broker_init(kafka_broker_t *brock);
void kafka_broker_deinit(kafka_broker_t *broker);

void kafka_config_init(kafka_config_t *config);
void kafka_config_deinit(kafka_config_t *config);

void kafka_meta_init(kafka_meta_t *meta);
void kafka_meta_deinit(kafka_meta_t *meta);

void kafka_partition_init(kafka_partition_t *partition);
void kafka_partition_deinit(kafka_partition_t *partition);

void kafka_member_init(kafka_member_t *member);
void kafka_member_deinit(kafka_member_t *member);

void kafka_record_init(kafka_record_t *record);
void kafka_record_deinit(kafka_record_t *record);

void kafka_record_header_init(kafka_record_header_t *header);
void kafka_record_header_deinit(kafka_record_header_t *header);

void kafka_api_init(kafka_api_t *api);
void kafka_api_deinit(kafka_api_t *api);

void kafka_sasl_init(kafka_sasl_t *sasl);
void kafka_sasl_deinit(kafka_sasl_t *sasl);

int kafka_topic_partition_set_tp(const char *topic_name, int partition,
								 kafka_topic_partition_t *toppar);

int kafka_record_set_key(const void *key, size_t key_len,
						 kafka_record_t *record);

int kafka_record_set_value(const void *val, size_t val_len,
						   kafka_record_t *record);

int kafka_record_header_set_kv(const void *key, size_t key_len,
							   const void *val, size_t val_len,
							   kafka_record_header_t *header);

int kafka_meta_set_topic(const char *topic_name, kafka_meta_t *meta);

int kafka_cgroup_set_group(const char *group_name, kafka_cgroup_t *cgroup);

int kafka_broker_get_api_version(const kafka_api_t *broker, int api_key,
								 int min_ver, int max_ver);

unsigned kafka_get_features(kafka_api_version_t *api, size_t api_cnt);

int kafka_api_version_is_queryable(const char *broker_version,
								   kafka_api_version_t **api,
								   size_t *api_cnt);

int kafka_sasl_set_mechanisms(kafka_config_t *conf);
int kafka_sasl_set_username(const char *username, kafka_config_t *conf);
int kafka_sasl_set_password(const char *passwd, kafka_config_t *conf);

#ifdef __cplusplus
}
#endif

#endif


target("basic_protocol")
    set_kind("object")
    add_files("PackageWrapper.cc",
              "SSLWrapper.cc",
              "dns_parser.c",
              "DnsMessage.cc",
              "DnsUtil.cc",
              "http_parser.c",
              "HttpMessage.cc",
              "HttpUtil.cc")

target("mysql_protocol")
    if (get_config("mysql") == true) then
        add_files("mysql_stream.c",
                  "mysql_parser.c",
                  "mysql_byteorder.c",
                  "MySQLMessage.cc",
                  "MySQLResult.cc",
                  "MySQLUtil.cc")
        set_kind("object")
        add_deps("basic_protocol")
    else
        set_kind("phony")
    end

target("redis_protocol")
    if (get_config("redis") == true) then
        add_files("redis_parser.c", "RedisMessage.cc")
        set_kind("object")
        add_deps("basic_protocol")
    else
        set_kind("phony")
    end

target("protocol")
    set_kind("object")
    add_deps("basic_protocol", "mysql_protocol", "redis_protocol")

target("kafka_message")
    if (get_config("kafka") == true) then
        add_files("KafkaMessage.cc")
        set_kind("object")
        add_cxxflags("-fno-rtti")
        add_packages("lz4", "zstd", "zlib", "snappy")
    else
        set_kind("phony")
    end

target("kafka_protocol")
    if (get_config("kafka") == true) then
        set_kind("object")
        add_files("kafka_parser.c",
                  "KafkaDataTypes.cc",
                  "KafkaResult.cc")
        add_deps("kafka_message", "protocol")
    else
        set_kind("phony")
    end